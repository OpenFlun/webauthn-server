/**
 * 一套运行时无关的 Base64URL 编码处理工具集
 * @module
 */
import { base64 } from '@hexagon/base64';


/**
 * 将给定的 ArrayBuffer 编码为 Base64URL 字符串,适合将各类凭证响应中的 ArrayBuffer 转为字符串,
 * 以便作为 JSON 发送回服务器;
 * - 查看定义:@see {@link fromBuffer}
 * @param {ArrayBuffer|Uint8Array} buffer 要编码的值
 * @param {string} [to='base64url'] 指定编码格式,如需编码为普通 Base64 可设为 'base64'
 * @returns {string}
 */
const fromBuffer = (buffer, to = 'base64url') => {
    /**
     * 优雅处理 Uint8Array 的子类(如 Node.js 的 Buffer),这些类型可能拥有较大的 ArrayBuffer 作为后端存储;
     */
    const _normalized = new Uint8Array(buffer);
    return base64.fromArrayBuffer(_normalized.buffer, to === 'base64url');
};

/**
 * 将 UTF-8 字符串编码为 Base64URL
 * - 查看定义:@see {@link utf8Tob64url}
 * @param {string} utf8String
 * @returns {string}
 */
const utf8Tob64url = utf8String => {
    return base64.fromString(utf8String, true);
};
/**
 * 将 Base64URL 编码的字符串解码为 ArrayBuffer;最适合用于将凭证 ID 从 JSON 字符串转换为 ArrayBuffer,
 * 例如在 allowCredentials 或 excludeCredentials 中使用;
 * - 查看定义:@see {@link toBuffer}
 * @param {string} base64urlString 要解码的 Base64URL 字符串
 * @param {string} [from='base64url'] 指定编码格式,如需解码普通 Base64 可设为 'base64'
 * @returns {Uint8Array}
 */
const toBuffer = (base64urlString, from = 'base64url') => {
    const _buffer = base64.toArrayBuffer(base64urlString, from === 'base64url');
    return new Uint8Array(_buffer);
};
/**
* 将 Base64URL 字符串转换为普通 Base64 字符串
* - 查看定义:@see {@link toBase64}
* @param {string} base64urlString
* @returns {string}
*/
const toBase64 = base64urlString => {
    const fromBase64Url = base64.toArrayBuffer(base64urlString, true), toBase64 = base64.fromArrayBuffer(fromBase64Url);
    return toBase64;
};
/**
 * 将 Base64URL 字符串解码为原始 UTF-8 字符串
 * - 查看定义:@see {@link b64urlToUtf8}
 * @param {string} base64urlString
 * @returns {string}
 */
const b64urlToUtf8 = base64urlString => {
    return base64.toString(base64urlString, true);
};
/**
 * 确认字符串是否为普通 Base64 编码
 * - 查看定义:@see {@link isBase64}
 * @param {string} input
 * @returns {boolean}
 */
const isBase64 = input => {
    return base64.validate(input, false);
};
/**
 * 确认字符串是否为 Base64URL 编码,支持可选填充字符
 * - 查看定义:@see {@link isBase64URL}
 * @param {string} input
 * @returns {boolean}
 */
const isBase64URL = input => {
    input = trimPadding(input); // 如果存在填充字符,先将其移除
    return base64.validate(input, true);
};
/**
 * 移除 Base64URL 编码字符串中的可选填充字符('=')
 * - 查看定义:@see {@link trimPadding}
 * @param {string} input
 * @returns {string}
 */
const trimPadding = input => {
    return input.replace(/=/g, '');
};

export { fromBuffer, utf8Tob64url, toBuffer, toBase64, b64urlToUtf8, isBase64, isBase64URL, trimPadding };