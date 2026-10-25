import { COSEKEYS, isCOSEAlg } from '../cose.js';
import { fromBuffer } from './isoBase64URL.js';
import { getWebCrypto } from './getWebCrypto.js';
import { importKey } from './importKey.js';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg.js';
import { mapCoseAlgToWebCryptoKeyAlgName } from './mapCoseAlgToWebCryptoKeyAlgName.js';

/**
 * 使用 RSA COSE 公钥验证 PKCS#1 v1.5 或 PSS 签名
 *
 * - 查看定义:@see {@link verifyRSA}
 * @param {Object} opts - 验证选项
 * @param {Map<number, number | BufferSource>} opts.cosePublicKey - COSE 格式的 RSA 公钥,需包含 alg、n、e 字段
 * @param {BufferSource} opts.signature - 待验证的签名(原始格式)
 * @param {BufferSource} opts.data - 原始签名数据
 * @param {string} [opts.shaHashOverride] - 可选,强制使用的哈希算法名(如 'SHA-256'),优先级高于公钥中的 alg
 * @returns {Promise<boolean>} 验证通过返回 true,否则 false
 * @throws {Error} 当公钥缺少必要参数、alg 无效或算法不支持时抛出错误
 */
const verifyRSA = async opts => {
    const { cosePublicKey, signature, data, shaHashOverride } = opts, WebCrypto = await getWebCrypto(),
        alg = cosePublicKey.get(COSEKEYS.alg), n = cosePublicKey.get(COSEKEYS.n), e = cosePublicKey.get(COSEKEYS.e);

    if (!alg) throw new Error('公钥缺少 alg 字段 (RSA)');
    if (!isCOSEAlg(alg)) throw new Error(`公钥的 alg 值无效: ${alg} (RSA)`);
    if (!n) throw new Error('公钥缺少 n 字段 (RSA)');
    if (!e) throw new Error('公钥缺少 e 字段 (RSA)');

    const keyData = {
        kty: 'RSA', alg: '', n: fromBuffer(n), e: fromBuffer(e), ext: false
    },
        keyAlgorithm = { name: mapCoseAlgToWebCryptoKeyAlgName(alg), hash: { name: mapCoseAlgToWebCryptoAlg(alg) } },
        verifyAlgorithm = { name: mapCoseAlgToWebCryptoKeyAlgName(alg) };

    if (shaHashOverride) keyAlgorithm.hash.name = mapCoseAlgToWebCryptoAlg(shaHashOverride);
    if (keyAlgorithm.name === 'RSASSA-PKCS1-v1_5') {
        if (keyAlgorithm.hash.name === 'SHA-256') keyData.alg = 'RS256';
        else if (keyAlgorithm.hash.name === 'SHA-384') keyData.alg = 'RS384';
        else if (keyAlgorithm.hash.name === 'SHA-512') keyData.alg = 'RS512';
        else if (keyAlgorithm.hash.name === 'SHA-1') keyData.alg = 'RS1';
    } else if (keyAlgorithm.name === 'RSA-PSS') {
        /**
         * 盐长度,默认值为 20,但惯例是使用 hLen(哈希函数输出长度,单位字节);
         * 允许盐长度为零,此时会产生确定性的签名值;实际使用的盐长度可从签名值中确定;
         *
         * 来源:https://www.cryptosys.net/pki/manpki/pki_rsaschemes.html
         */
        let saltLength = 0;
        if (keyAlgorithm.hash.name === 'SHA-256') keyData.alg = 'PS256', saltLength = 32;      // 256 位 => 32 字节
        else if (keyAlgorithm.hash.name === 'SHA-384') keyData.alg = 'PS384', saltLength = 48; // 384 位 => 48 字节
        else if (keyAlgorithm.hash.name === 'SHA-512') keyData.alg = 'PS512', saltLength = 64; // 512 位 => 64 字节
        verifyAlgorithm.saltLength = saltLength;
    }
    else throw new Error(`意外的 RSA 密钥算法: ${alg} (${keyAlgorithm.name})`);

    const key = await importKey({ keyData, algorithm: keyAlgorithm });
    return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

export { verifyRSA };