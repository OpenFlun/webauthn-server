import { X509Certificate } from '@peculiar/x509';
import { isCertRevoked } from './isCertRevoked.js';
import { getWebCrypto } from './iso/getWebCrypto.js';

/**
 * 当证书链中某一证书的颁发者无法为下一证书签名,或根证书不自签名时抛出的内部错误;
 * - 查看定义:@see {@link InvalidSubjectAndIssuer}
 * @extends {Error}
 */
class InvalidSubjectAndIssuer extends Error {
    constructor() {
        const message = '证书主体与颁发者不匹配';
        super(message), this.name = 'InvalidSubjectAndIssuer';
    }
}

/**
 * 检查证书是否已被吊销,若已吊销则抛出错误
 * @param {X509Certificate} certificate
 */
const assertCertNotRevoked = async certificate => {
    const subjectCertRevoked = await isCertRevoked(certificate);
    if (subjectCertRevoked) throw new Error('证书路径中发现已被吊销的证书');
};

/**
 * 要求证书的当前时间处于其 notBefore 和 notAfter 的有效时间窗口内
 * @param {Date} certNotBefore
 * @param {Date} certNotAfter
 */
const assertCertIsWithinValidTimeWindow = (certNotBefore, certNotAfter) => {
    const now = new Date(Date.now());
    if (certNotBefore > now || certNotAfter < now) throw new Error('证书尚未生效或已过期');
};

/**
 * 遍历 PEM 证书数组,确保它们形成正确的证书链
 * - 查看定义:@see {@link validateCertificatePath}
 *
 * @param {string[]} x5cCertsPEM - 待验证的 X.509 证书链(PEM 格式),通常是 `x5c.map(convertASN1toPEM)` 的结果
 * @param {string[]} [trustAnchorsPEM=[]] - 信任锚证书列表(PEM 格式),用于验证 x5c 证书链的根信任
 * @returns {Promise<boolean>} 当证书路径验证成功时返回 true,否则抛出错误
 */
const validateCertificatePath = async (x5cCertsPEM, trustAnchorsPEM = []) => {
    if (trustAnchorsPEM.length === 0) return true; // 没有提供信任锚,跳过路径验证

    const WebCrypto = await getWebCrypto(),
        x5cCertsParsed = x5cCertsPEM.map((certPEM) => new X509Certificate(certPEM)); // 解析 x5c 证书

    // 检查 x5c 中是否有过期或时间无效的证书
    for (let i = 0; i < x5cCertsParsed.length; i++) {
        const cert = x5cCertsParsed[i], certPEM = x5cCertsPEM[i];

        try {
            await assertCertNotRevoked(cert);
        } catch (_err) {
            throw new Error(`x5c 中发现已被吊销的证书:\n${certPEM}`);
        }

        try {
            assertCertIsWithinValidTimeWindow(cert.notBefore, cert.notAfter);
        } catch (_err) {
            throw new Error(`x5c 中发现超出有效期范围的证书:\n${certPEM}`);
        }
    }

    // 解析信任锚证书
    const trustAnchorsParsed = trustAnchorsPEM.map((certPEM) => {
        try {
            return new X509Certificate(certPEM);
        } catch (err) {
            throw new Error(`无法解析信任锚证书:\n${certPEM}`, { cause: err });
        }
    }), validTrustAnchors = [];

    // 过滤掉过期或时间无效的信任锚证书
    for (let i = 0; i < trustAnchorsParsed.length; i++) {
        const cert = trustAnchorsParsed[i];
        try {
            await assertCertNotRevoked(cert);
        } catch (_err) { continue; } // 继续处理其他证书
        try {
            assertCertIsWithinValidTimeWindow(cert.notBefore, cert.notAfter);
        } catch (_err) { continue; } // 继续处理其他证书
        validTrustAnchors.push(cert);
    }
    if (validTrustAnchors.length === 0) throw new Error('没有可用于验证 x5c 的有效信任锚');

    // 尝试用每个信任锚验证 x5c
    let invalidSubjectAndIssuerError = false;
    for (const anchor of trustAnchorsParsed) {
        try {
            const x5cWithTrustAnchor = x5cCertsParsed.concat([anchor]);
            if (new Set(x5cWithTrustAnchor).size !== x5cWithTrustAnchor.length) {
                throw new Error('无效的证书路径:发现重复证书');
            }

            // 检查签名及 notBefore / notAfter
            for (let i = 0; i < x5cWithTrustAnchor.length - 1; i++) {
                const subject = x5cWithTrustAnchor[i], issuer = x5cWithTrustAnchor[i + 1],
                    // 叶证书或中间证书:确保链中的下一个证书为其签名
                    issuerSignedSubject = await subject.verify(
                        { publicKey: issuer.publicKey, signatureOnly: true }, WebCrypto);

                if (!issuerSignedSubject) throw new InvalidSubjectAndIssuer();
                if (issuer.subject === issuer.issuer) {
                    // 检测到根证书,确保它是自签名的
                    const issuerSignedIssuer = await issuer.verify(
                        { publicKey: issuer.publicKey, signatureOnly: true }, WebCrypto);
                    if (!issuerSignedIssuer) throw new InvalidSubjectAndIssuer();
                    break; // 遇到根证书后不再继续处理链中的后续证书
                }
            }

            // 如果成功验证了一条路径,则无需继续尝试其他信任锚,同时清除之前信任锚产生的错误标记
            invalidSubjectAndIssuerError = false;
            break;
        } catch (err) {
            if (err instanceof InvalidSubjectAndIssuer) invalidSubjectAndIssuerError = true;
            else throw new Error('验证证书路径时发生意外错误', { cause: err });
        }
    }

    // 尝试了多个信任锚,均未成功
    if (invalidSubjectAndIssuerError) throw new InvalidSubjectAndIssuer();
    return true;
};

export { validateCertificatePath, InvalidSubjectAndIssuer };