import { verify } from './iso/index.js';
import { decodeCredentialPublicKey } from './decodeCredentialPublicKey.js';
import { convertX509PublicKeyToCOSE } from './convertX509PublicKeyToCOSE.js';

/**
 * 用于在测试时模拟返回值
 * - 查看定义:@see {@link _verifySignatureInternals}
 * @ignore 不要将此内容包含在文档输出中
 * @type {{ stubThis: (value: unknown) => unknown }}
 */
const _verifySignatureInternals = { stubThis: value => value };

/**
 * 验证身份验证器的签名
 * - 查看定义:@see {@link verifySignature}
 * @param {Object} opts - 签名验证选项
 * @param {BufferSource} opts.signature - 待验证的签名
 * @param {BufferSource} opts.data - 签名的原始数据
 * @param {BufferSource} [opts.credentialPublicKey] - 凭证公钥(COSE 编码)
 * @param {BufferSource} [opts.x509Certificate] - X.509 证书(DER 格式)
 * @param {string} [opts.hashAlgorithm] - 哈希算法覆盖值
 * @returns {Promise<boolean>} 签名有效时返回 true,否则抛出错误
 */
const verifySignature = opts => {
    const { signature, data, credentialPublicKey, x509Certificate, hashAlgorithm, } = opts;
    if (!x509Certificate && !credentialPublicKey) throw new Error('必须声明 "leafCert" 或 "credentialPublicKey" 其中之一');
    if (x509Certificate && credentialPublicKey) throw new Error('不能同时声明 "leafCert" 和 "credentialPublicKey"');
    let cosePublicKey = new Map();
    if (credentialPublicKey) cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
    else if (x509Certificate) cosePublicKey = convertX509PublicKeyToCOSE(x509Certificate);
    return _verifySignatureInternals.stubThis(verify({
        cosePublicKey, signature, data, shaHashOverride: hashAlgorithm
    }));
};

export { _verifySignatureInternals, verifySignature };