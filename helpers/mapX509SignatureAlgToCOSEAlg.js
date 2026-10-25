import { COSEALG } from './cose.js';

/**
 * 将 X.509 签名算法 OID 映射为 COSE 算法 ID
 * - 查看定义:@see {@link mapX509SignatureAlgToCOSEAlg}
 * - EC2 的 OID:https://oidref.com/1.2.840.10045.4.3
 * - RSA 的 OID:https://oidref.com/1.2.840.113549.1.1
 *
 * @param {string} signatureAlgorithm - X.509 签名算法的 OID 字符串
 * @returns {number} 对应的 COSE 算法标识符
 */
const mapX509SignatureAlgToCOSEAlg = signatureAlgorithm => {
    let alg;
    if (signatureAlgorithm === '1.2.840.10045.4.3.2') alg = COSEALG.ES256;
    else if (signatureAlgorithm === '1.2.840.10045.4.3.3') alg = COSEALG.ES384;
    else if (signatureAlgorithm === '1.2.840.10045.4.3.4') alg = COSEALG.ES512;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.11') alg = COSEALG.RS256;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.12') alg = COSEALG.RS384;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.13') alg = COSEALG.RS512;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.5') alg = COSEALG.RS1;
    else throw new Error(`无法将 X.509 签名算法 ${signatureAlgorithm} 映射为 COSE 算法`);
    return alg;
};

export { mapX509SignatureAlgToCOSEAlg };