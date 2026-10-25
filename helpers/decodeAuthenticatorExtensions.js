import { decodeFirst } from './iso/index.js';

/**
 * CBOR 编码的扩展可能包含深层嵌套的 Map,这对于简单的 `Object.entries()` 来说过深;
 * 此方法将递归确保所有 Map 都被转换为基本对象;
 *
 * @param {Map<string, unknown>} input - 需要转换的 Map 结构
 * @returns {Record<string, unknown>} 转换后的普通对象
 */
const convertMapToObjectDeep = input => {
    const mapped = {};
    for (const [key, value] of input) {
        if (value instanceof Map) mapped[key] = convertMapToObjectDeep(value);
        else mapped[key] = value;
    }
    return mapped;
};

/**
 * 将身份验证器扩展数据缓冲区转换为相应的对象
 * - 查看定义:@see {@link decodeAuthenticatorExtensions}
 *
 * @param {BufferSource} extensionData - 身份验证器扩展数据缓冲区(CBOR 编码)
 * @returns {Record<string, unknown>} 解码并转换为普通对象的扩展数据
 */
const decodeAuthenticatorExtensions = extensionData => {
    let toCBOR;
    try {
        toCBOR = decodeFirst(extensionData);
    }
    catch (err) {
        throw new Error(`解码身份验证器扩展时出错:${err.message}`);
    }
    return convertMapToObjectDeep(toCBOR);
};

export { decodeAuthenticatorExtensions };