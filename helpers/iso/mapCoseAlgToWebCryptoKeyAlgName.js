import { COSEALG } from '../cose.js';

/**
 * 将 COSE 算法标识符转换为 WebCrypto API 所期望的对应密钥算法字符串值
 * - 查看定义:@see {@link mapCoseAlgToWebCryptoKeyAlgName}
 *
 * @param {number} alg - COSE 算法标识符(来自 COSEALG 常量)
 * @returns {string} WebCrypto 兼容的密钥算法名称(例如 'Ed25519'、'ECDSA'、'RSASSA-PKCS1-v1_5' 或 'RSA-PSS')
 */
const mapCoseAlgToWebCryptoKeyAlgName = alg => {
    if ([COSEALG.EdDSA].indexOf(alg) >= 0) return 'Ed25519';
    else if ([COSEALG.ES256, COSEALG.ES384, COSEALG.ES512, COSEALG.ES256K].indexOf(alg) >= 0) return 'ECDSA';
    else if ([COSEALG.RS256, COSEALG.RS384, COSEALG.RS512, COSEALG.RS1].indexOf(alg) >= 0) return 'RSASSA-PKCS1-v1_5';
    else if ([COSEALG.PS256, COSEALG.PS384, COSEALG.PS512].indexOf(alg) >= 0) return 'RSA-PSS';

    throw new Error(`无法将 COSE 算法值 ${alg} 映射为 WebCrypto 密钥算法名称`);
}

export { mapCoseAlgToWebCryptoKeyAlgName };