import { decodeFirst } from './iso/index.js';

/**
 * 使得在测试期间可以模拟(stub)返回值
 * - 查看定义:@see {@link _decodeCredentialPublicKeyInternals}
 * @type {{ stubThis: <T>(value: T) => T }}
 * @ignore 不要在文档输出中包含此项
 */
const _decodeCredentialPublicKeyInternals = { stubThis: value => value };

/**
 * 将 WebAuthn 凭证公钥(CBOR 编码的 COSE 公钥)解码为 COSEPublicKey Map 对象
 *
 * @param {BufferSource} publicKey - 来自 authenticatorData 的凭证公钥缓冲区(CBOR 编码的 COSE_Key)
 * @returns {Map<number, number | BufferSource>} 解码后的 COSE 公钥 Map,
 *   可通过类型守卫(isCOSEPublicKeyOKP / EC2 / RSA)进一步细化类型
 * @throws {Error} 如果输入不是有效的 CBOR 结构或不包含预期的 COSE 密钥参数,将抛出错误;
 * - 查看定义:@see {@link decodeCredentialPublicKey}
 * - {@link https://www.w3.org/TR/webauthn-2/#sctn-public-key-easy|WebAuthn Credential Public Key}
 * - {@link https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-map|COSE Key Map Specification}
 */
const decodeCredentialPublicKey = publicKey => {
    return _decodeCredentialPublicKeyInternals.stubThis(decodeFirst(publicKey));
}

export { _decodeCredentialPublicKeyInternals, decodeCredentialPublicKey };