import { toHex } from './iso/index.js';

/**
 * 将 authData 中的 aaguid 缓冲区转换为 UUID 字符串
 * - 查看定义:@see {@link convertAAGUIDToString}
 *
 * @param {BufferSource} aaguid - 16 字节的 AAGUID 缓冲区
 * @returns {string} 格式化后的 UUID 字符串(如 "adce0002-35bc-c60a-648b-0b25f1f05503")
 */
const convertAAGUIDToString = aaguid => {
    // Raw Hex: adce000235bcc60a648b0b25f1f05503
    const hex = toHex(aaguid),
        segments = [
            hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)
        ];
    return segments.join('-'); // Formatted: adce0002-35bc-c60a-648b-0b25f1f05503
};

export { convertAAGUIDToString };