import { COSECRV, COSEKEYS, isCOSEAlg } from '../cose.js';
import { fromBuffer } from './isoBase64URL.js';
import { getWebCrypto } from './getWebCrypto.js';
import { importKey } from './importKey.js';

/**
 * 使用 OKP(Octet Key Pair,如 Ed25519)COSE 公钥验证签名
 *
 * - 查看定义:@see {@link verifyOKP}
 * @param {Object} opts - 验证选项
 * @param {Map<number, number | BufferSource>} opts.cosePublicKey - COSE 格式的 OKP 公钥,需包含 alg、crv、x 字段
 * @param {BufferSource} opts.signature - 待验证的签名(原始字节序列)
 * @param {BufferSource} opts.data - 原始签名数据
 * @returns {Promise<boolean>} 验证通过返回 true,否则 false
 * @throws {Error} 当公钥缺少必要字段、算法无效或曲线不支持时抛出错误
 */
const verifyOKP = async opts => {
    const { cosePublicKey, signature, data } = opts, WebCrypto = await getWebCrypto(),
        alg = cosePublicKey.get(COSEKEYS.alg), crv = cosePublicKey.get(COSEKEYS.crv), x = cosePublicKey.get(COSEKEYS.x);

    if (!alg) throw new Error('公钥缺少 alg 字段 (OKP)');
    if (!isCOSEAlg(alg)) throw new Error(`公钥包含无效的 alg 值 ${alg} (OKP)`);
    if (!crv) throw new Error('公钥缺少 crv 字段 (OKP)');
    if (!x) throw new Error('公钥缺少 x 字段 (OKP)');

    // 密钥导入步骤参考:
    // https://wicg.github.io/webcrypto-secure-curves/#ed25519-operations
    let _crv;
    if (crv === COSECRV.ED25519) _crv = 'Ed25519';
    else throw new Error(`不支持的 COSE crv 值 ${crv} (OKP)`);

    const keyData = {
        kty: 'OKP', crv: _crv, alg: 'EdDSA', x: fromBuffer(x), ext: false,
    },
        keyAlgorithm = { name: _crv, namedCurve: _crv },
        key = await importKey({ keyData, algorithm: keyAlgorithm }),
        verifyAlgorithm = { name: _crv };

    return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

export { verifyOKP };