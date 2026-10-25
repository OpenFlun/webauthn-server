import { getWebCrypto } from './getWebCrypto.js';
/**
 * 导入一个用于签名验证的 JSON Web Key (JWK) 格式密钥;
 *
 * 该函数从 `getWebCrypto` 获取 Web Crypto API 实例,然后使用 `subtle.importKey` 方法
 * 将 JWK 格式的密钥数据导入为 `CryptoKey` 对象,该密钥仅限于 `verify` 操作;
 * - 查看定义:@see {@link importKey}
 * @param {Object} opts - 配置选项;
 * @param {JsonWebKey} opts.keyData - JWK 格式的密钥数据,需包含密钥类型、算法参数等必要字段;
 * @param {Object} opts.algorithm - 密钥对应的算法标识符或算法参数对象,
 *   例如 `{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }`;
 * @returns {Promise<CryptoKey>} 返回一个 Promise,成功时解析为可用于 `verify` 操作的 `CryptoKey` 对象;
 */
const importKey = async opts => {
    const WebCrypto = await getWebCrypto(), { keyData, algorithm } = opts;
    return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
}

export { importKey };