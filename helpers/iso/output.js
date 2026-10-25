import { isCOSEPublicKeyEC2, isCOSECrv, isCOSEPublicKeyRSA, isCOSEPublicKeyOKP, COSEKEYS } from '../cose.js';
import { getWebCrypto } from './getWebCrypto.js';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg.js';
import { unwrapEC2Signature } from './unwrapEC2Signature.js';
import { verifyEC2 } from './verifyEC2.js';
import { verifyRSA } from './verifyRSA.js';
import { verifyOKP } from './verifyOKP.js';

// ================================= digest函数 =================================
/**
 * 生成所提供数据的摘要(哈希值)
 * - 查看定义:@see {@link digest}
 * @param {BufferSource} data - 要生成摘要的数据
 * @param {number} algorithm - COSE 算法 ID,该 ID 映射到所需的 SHA 算法
 * @returns {Promise<Uint8Array>} 包含摘要字节的 Uint8Array
 */
const digest = async (data, algorithm) => {
    const WebCrypto = await getWebCrypto(), subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm),
        hashed = await WebCrypto.subtle.digest(subtleAlgorithm, data);
    return new Uint8Array(hashed);
};

// ================================= getRandomValues函数 =================================
/**
 * 使用与数组长度相等的随机字节填充传入的字节数组
 * - 查看定义:@see {@link getRandomValues}
 *
 * @template T
 * @param {T} array - 要填充随机值的类型化数组(如 Uint8Array)
 * @returns {Promise<T>} 返回传入的同一个字节数组(已填充随机值)
 */
const getRandomValues = async array => {
    const WebCrypto = await getWebCrypto();
    WebCrypto.getRandomValues(array);
    return array;
}

// ================================= getRandomValues函数 =================================
/**
 * 使用 COSE 格式公钥验证签名,支持 EC2、RSA 和 OKP 密钥类型
 * - 查看定义:@see {@link verify}
 * @param {Object} opts - 验证选项
 * @param {Map<number, number | BufferSource>} opts.cosePublicKey - COSE 格式的公钥(包含必要的密钥参数)
 * @param {BufferSource} opts.signature - 待验证的签名(原始 ASN.1 或 COSE 格式)
 * @param {BufferSource} opts.data - 已签名的原始数据
 * @param {string} [opts.shaHashOverride] - 可选,覆盖默认的哈希算法(如 'SHA-256')
 * @returns {Promise<boolean>} 验证通过返回 true,否则 false
 * @throws {Error} 当公钥类型不支持、曲线未知或签名格式无效时抛出错误
 */
const verify = opts => {
    const { cosePublicKey, signature, data, shaHashOverride } = opts;

    if (isCOSEPublicKeyEC2(cosePublicKey)) {
        const crv = cosePublicKey.get(COSEKEYS.crv);
        if (!isCOSECrv(crv)) throw new Error(`未知的 COSE 曲线 ${crv}`);

        const unwrappedSignature = unwrapEC2Signature(signature, crv);
        return verifyEC2({ cosePublicKey, signature: unwrappedSignature, data, shaHashOverride });
    }
    else if (isCOSEPublicKeyRSA(cosePublicKey)) return verifyRSA({ cosePublicKey, signature, data, shaHashOverride });
    else if (isCOSEPublicKeyOKP(cosePublicKey)) return verifyOKP({ cosePublicKey, signature, data });

    const kty = cosePublicKey.get(COSEKEYS.kty);
    throw new Error(`此方法不支持使用 kty 为 ${kty} 的公钥进行签名验证`);
};

export { digest, getRandomValues, verify };