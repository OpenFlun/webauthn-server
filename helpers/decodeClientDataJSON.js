import { b64urlToUtf8 } from './iso/index.js';

/**
 * 使测试期间能够模拟(stub)返回值
 * - 查看定义:@see {@link _decodeClientDataJSONInternals}
 * @ignore 不要将此内容包含在文档输出中
 * @type {{ stubThis: <T>(value: T) => T }}
 */
const _decodeClientDataJSONInternals = { stubThis: value => value };

/**
 * 将身份验证器的 base64url 编码的 clientDataJSON 解码为 JSON 对象
 * - 查看定义:@see {@link decodeClientDataJSON}
 *
 * @param {string} data - base64url 编码的 clientDataJSON 字符串
 * @returns {Record<string, unknown>} 解码后的 ClientData 对象(JavaScript 友好格式)
 */
const decodeClientDataJSON = data => {
    const toString = b64urlToUtf8(data), clientData = JSON.parse(toString);
    return _decodeClientDataJSONInternals.stubThis(clientData);
};

export { _decodeClientDataJSONInternals, decodeClientDataJSON };