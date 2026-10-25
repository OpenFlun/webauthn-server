import {
    AuthorityKeyIdentifierExtension, CRLDistributionPointsExtension,
    SubjectKeyIdentifierExtension, X509Crl
} from '@peculiar/x509';
import { fetch } from './fetch.js';

/**
 * 缓存已吊销证书的映射表,键为 CA 的密钥标识符,值为包含吊销证书序列号列表及下次更新时间的对象
 */
const cacheRevokedCerts = {};

/**
 * 从证书中获取 CRL 分发点,下载 CRL 并比对证书序列号是否在吊销列表中;
 * - 查看定义:@see {@link isCertRevoked}
 * - CRL 证书结构参考 https://tools.ietf.org/html/rfc5280#page-117
 *
 * @typedef {Object} X509Certificate
 * @property {string} serialNumber - 证书序列号(十六进制字符串)
 * @property {Array<import('@peculiar/x509').Extension>} [extensions] - 证书扩展项列表
 *
 * @param {X509Certificate} cert - 要检查吊销状态的证书(X.509 证书实例,通常来自 @peculiar/x509)
 * @returns {Promise<boolean>} 如果证书已被吊销则返回 `true`,否则返回 `false`
 */
const isCertRevoked = async cert => {
    const { extensions } = cert;
    if (!extensions) return false;

    let extAuthorityKeyID, extSubjectKeyID, extCRLDistributionPoints, keyIdentifier = undefined;
    extensions.forEach((ext) => {
        if (ext instanceof AuthorityKeyIdentifierExtension) extAuthorityKeyID = ext;
        else if (ext instanceof SubjectKeyIdentifierExtension) extSubjectKeyID = ext;
        else if (ext instanceof CRLDistributionPointsExtension) extCRLDistributionPoints = ext;
    });

    // 尝试获取证书颁发机构(CA)的密钥标识符,用于缓存
    if (extAuthorityKeyID && extAuthorityKeyID.keyId) keyIdentifier = extAuthorityKeyID.keyId;
    // 当前证书可能是自签名的根证书,尝试使用主体密钥标识符扩展
    else if (extSubjectKeyID) keyIdentifier = extSubjectKeyID.keyId;

    if (keyIdentifier) {
        const cached = cacheRevokedCerts[keyIdentifier];
        if (cached) {
            const now = new Date();
            // 如果缓存中定义了 nextUpdate 且尚未过期,则直接使用缓存数据
            if (!cached.nextUpdate || cached.nextUpdate > now) return cached.revokedCerts.indexOf(cert.serialNumber) >= 0;
        }
    }

    // 从 CRL 分发点扩展中提取 CRL 的 URL 地址
    const crlURL = extCRLDistributionPoints?.distributionPoints?.[0].distributionPoint?.fullName?.[0]
        .uniformResourceIdentifier;
    if (!crlURL) return false; // 若未提供 CRL 下载地址,则无法检查,视为未吊销

    // 下载 CRL 数据
    let certListBytes;
    try {
        const respCRL = await fetch(crlURL);
        certListBytes = await respCRL.arrayBuffer();
    } catch (_err) {
        return false;
    }

    let data;
    try {
        data = new X509Crl(certListBytes);
    } catch (_err) {
        return false; // CRL 数据格式错误,视为未吊销
    }

    const newCached = { revokedCerts: [], nextUpdate: undefined };
    // 记录下次更新时间
    if (data.nextUpdate) newCached.nextUpdate = data.nextUpdate;

    // 提取吊销证书序列号列表
    const revokedCerts = data.entries;
    if (revokedCerts) {
        for (const certEntry of revokedCerts) {
            const revokedHex = certEntry.serialNumber;
            newCached.revokedCerts.push(revokedHex);
        }

        // 将结果存入缓存
        if (keyIdentifier) cacheRevokedCerts[keyIdentifier] = newCached;
        return newCached.revokedCerts.indexOf(cert.serialNumber) >= 0;
    }

    return false;
};

export { isCertRevoked };