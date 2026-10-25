import { decodePartialCBOR, encodeCBOR } from '@levischuck/tiny-cbor';

/**
 * 无论使用何种 CBOR 编码器,当数据重新编码时,都应保持 CBOR 数据的长度不变
 *
 * 最关键的是,我们使用的 CBOR 库必须满足以下要求:
 * - CBOR Map 类型值解码后必须是 JavaScript 的 Map 对象
 * - 将 Uint8Array 编码回 CBOR 时,不得使用 CBOR 标签 64(uint8 类型数组)
 *
 * 只要满足这些要求,CBOR 序列就可以自由地编解码,同时保持其长度,从而能够最精确地在各序列间移动指针;
 */

/**
 * 解码并返回一个 CBOR 编码值序列中的第一个项
 * - 查看定义:@see {@link decodeFirst}
 * @param {BufferSource} input - 要解码的 CBOR 数据
 * @returns {unknown} 解码后的第一个 CBOR 项(可能是 Map、Array、number、string 等)
 */
const decodeFirst = input => {
    // 复制一份,避免修改原始数据
    const _input = new Uint8Array(input), decoded = decodePartialCBOR(_input, 0), [first] = decoded;
    return first;
};

/**
 * 将数据编码为 CBOR
 * - 查看定义:@see {@link encode}
 * @param {unknown} input - 要编码的数据(支持 Map、Array、number、string、Uint8Array 等 CBOR 兼容类型)
 * @returns {Uint8Array} 编码后的 CBOR 字节序列
 */
const encode = input => {
    return encodeCBOR(input);
};

export { decodeFirst, encode };