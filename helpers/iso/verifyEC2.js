import { COSECRV, COSEKEYS } from '../cose.js';
import { fromBuffer } from './isoBase64URL.js';
import { getWebCrypto } from './getWebCrypto.js';
import { importKey } from './importKey.js';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg.js';

/**
 * 使用 EC2(椭圆曲线)COSE 公钥验证 ECDSA 签名
 *
 * 查看定义:@see {@link verifyEC2}
 * @param {Object} opts - 验证选项
 * @param {Map<number, number | BufferSource>} opts.cosePublicKey - COSE 格式的 EC2 公钥,需包含 alg、crv、x、y 字段
 * @param {BufferSource} opts.signature - 待验证的签名(已规范化,r||s 拼接格式)
 * @param {BufferSource} opts.data - 原始签名数据
 * @param {string} [opts.shaHashOverride] - 可选,强制使用的哈希算法名(如 'SHA-256'),优先级高于公钥中的 alg
 * @returns {Promise<boolean>} 验证通过返回 true,否则 false
 * @throws {Error} 当公钥缺少必要参数、曲线不支持或导入密钥失败时抛出错误
 */
const verifyEC2 = async opts => {
    const { cosePublicKey, signature, data, shaHashOverride } = opts, WebCrypto = await getWebCrypto(),
        // 导入公钥
        alg = cosePublicKey.get(COSEKEYS.alg), crv = cosePublicKey.get(COSEKEYS.crv),
        x = cosePublicKey.get(COSEKEYS.x), y = cosePublicKey.get(COSEKEYS.y);

    if (!alg) throw new Error('公钥缺少 alg 参数 (EC2)');
    if (!crv) throw new Error('公钥缺少 crv 参数 (EC2)');
    if (!x) throw new Error('公钥缺少 x 参数 (EC2)');
    if (!y) throw new Error('公钥缺少 y 参数 (EC2)');

    let _crv;
    if (crv === COSECRV.P256) _crv = 'P-256';
    else if (crv === COSECRV.P384) _crv = 'P-384';
    else if (crv === COSECRV.P521) _crv = 'P-521';
    else throw new Error(`意外的 COSE crv 值:${crv} (EC2)`);

    const keyData = {
        kty: 'EC', crv: _crv,
        x: fromBuffer(x), y: fromBuffer(y), ext: false,
    },
        keyAlgorithm = {
            /**
             * 给未来的自己:此处不能使用 `mapCoseAlgToWebCryptoKeyAlgName()`,因为来自真实设备的部分叶子证书
             * 在 `alg` 中指定了 RSA SHA 值(例如 `-257`),这会被映射为 `'RSASSA-PKCS1-v1_5'`;
             * 这里我们始终需要 `'ECDSA'`,因此直接硬编码;
             */
            name: 'ECDSA', namedCurve: _crv,
        }, key = await importKey({ keyData, algorithm: keyAlgorithm });

    // 确定用于签名验证的 SHA 算法
    let subtleAlg = mapCoseAlgToWebCryptoAlg(alg);
    if (shaHashOverride) subtleAlg = mapCoseAlgToWebCryptoAlg(shaHashOverride);

    const verifyAlgorithm = { name: 'ECDSA', hash: { name: subtleAlg } };
    return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

export { verifyEC2 };