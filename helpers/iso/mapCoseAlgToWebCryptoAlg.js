import { COSEALG } from '../cose.js';

/**
 * 将 COSE 算法 ID 转换为 WebCrypto API 所期望的对应字符串值
 * - 查看定义:@see {@link mapCoseAlgToWebCryptoAlg}
 * @param {number} alg - COSE 算法标识符(来自 COSEALG 常量)
 * @returns {string} 对应的 WebCrypto 算法名称(如 "SHA-256")
 */
const mapCoseAlgToWebCryptoAlg = alg => {
    if ([COSEALG.RS1].indexOf(alg) >= 0) return 'SHA-1';
    else if ([COSEALG.ES256, COSEALG.PS256, COSEALG.RS256].indexOf(alg) >= 0) return 'SHA-256';
    else if ([COSEALG.ES384, COSEALG.PS384, COSEALG.RS384].indexOf(alg) >= 0) return 'SHA-384';
    else if ([COSEALG.ES512, COSEALG.PS512, COSEALG.RS512, COSEALG.EdDSA].indexOf(alg) >= 0) return 'SHA-512';

    throw new Error(`无法将 COSE 算法值 ${alg} 映射为 WebCrypto 算法`);
}

export { mapCoseAlgToWebCryptoAlg };