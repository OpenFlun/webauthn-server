import { utf8Tobytes, digest } from './iso/index.js';

/**
 * 返回给定数据的哈希摘要,如果提供了算法参数,则使用指定的算法,默认使用 SHA-256
 * - 查看定义:@see {@link toHash}
 *
 * @param {string | BufferSource} data - 要计算哈希的原始数据
 * @param {number} [algorithm=-7] - COSE 算法标识符,默认为 -7 (SHA-256)
 * @returns {Promise<ArrayBuffer>} 解析为包含哈希摘要的 ArrayBuffer 的 Promise
 */
const toHash = (data, algorithm = -7) => {
    if (typeof data === 'string') data = utf8Tobytes(data);
    const digestV = digest(data, algorithm);
    return digestV;
};

export { toHash };