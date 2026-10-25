import { AsnParser } from '@peculiar/asn1-schema';
import { BasicConstraints, Certificate, id_ce_basicConstraints } from '@peculiar/asn1-x509';

/**
 * 将 OID 映射为可读的证书字段名
 * @type {Record<string, string>}
 */
const issuerSubjectIDKey = {
    '2.5.4.6': 'C',      // 国家
    '2.5.4.10': 'O',     // 组织
    '2.5.4.11': 'OU',    // 组织单元
    '2.5.4.3': 'CN',     // 通用名称
};

/**
 * 将颁发者或主体信息中的各个部分拼接成字符串,以便于比较;
 *
 * 拼接顺序看似随意,实际是固定的(C, O, OU, CN),保证字符串化时顺序一致即可;
 *
 * @param {Object} input - 包含 C/O/OU/CN 字段的对象
 * @param {string} [input.C] - 国家
 * @param {string} [input.O] - 组织
 * @param {string} [input.OU] - 组织单元
 * @param {string} [input.CN] - 通用名称
 * @returns {string} 拼接后的字符串
 */
const issuerSubjectToString = input => {
    const parts = [];
    if (input.C) parts.push(input.C);
    if (input.O) parts.push(input.O);
    if (input.OU) parts.push(input.OU);
    if (input.CN) parts.push(input.CN);
    return parts.join(' : ');
};

/**
 * 提取 PEM 证书信息
 * - 查看定义:@see {@link getCertificateInfo}
 *
 * @param {ArrayBuffer} leafCertBuffer - 由 convertASN1toPEM(x5c[0]) 返回的证书缓冲区(DER 格式)
 * @returns {{
 *   issuer: Record<string, string>,
 *   subject: Record<string, string>,
 *   version: number,
 *   basicConstraintsCA: boolean,
 *   notBefore: number,
 *   notAfter: number,
 *   parsedCertificate: Certificate
 * }} 解析后的证书信息
 */
const getCertificateInfo = leafCertBuffer => {
    const x509 = AsnParser.parse(leafCertBuffer, Certificate), parsedCert = x509.tbsCertificate,
        issuer = { combined: '' }, subject = { combined: '' };

    // 颁发者(Issuer)
    parsedCert.issuer.forEach(([iss]) => {
        const key = issuerSubjectIDKey[iss.type];
        if (key) issuer[key] = iss.value.toString();
    });
    issuer.combined = issuerSubjectToString(issuer);

    // 主体(Subject)
    parsedCert.subject.forEach(([iss]) => {
        const key = issuerSubjectIDKey[iss.type];
        if (key) subject[key] = iss.value.toString();
    });
    subject.combined = issuerSubjectToString(subject);

    let basicConstraintsCA = false;
    if (parsedCert.extensions) {
        // 遍历扩展项,查找 BasicConstraints 扩展
        for (const ext of parsedCert.extensions) {
            if (ext.extnID === id_ce_basicConstraints) {
                const basicConstraints = AsnParser.parse(ext.extnValue, BasicConstraints);
                basicConstraintsCA = basicConstraints.cA;
            }
        }
    }

    return {
        issuer,                                             // 颁发者信息
        subject,                                            // 主体信息
        version: parsedCert.version,                        // 证书版本
        basicConstraintsCA,                                 // 是否为 CA 证书
        notBefore: parsedCert.validity.notBefore.getTime(), // 生效时间(毫秒时间戳)
        notAfter: parsedCert.validity.notAfter.getTime(),   // 失效时间(毫秒时间戳)
        parsedCertificate: x509,                            // 完整解析后的证书对象
    };
};

export { getCertificateInfo, issuerSubjectToString };