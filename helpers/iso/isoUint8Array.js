/**
 * 将十六进制字符串转换为 Uint8Array;
 * - 查看定义:@see {@link fromHex}
 * 替代 `Buffer.from('...', 'hex')`
 * @param {string} hex - 十六进制字符串(可包含大小写字母,长度必须为偶数)
 * @returns {Uint8Array} 转换后的字节数组
 */
const fromHex = hex => {
    if (!hex) return Uint8Array.from([]);

    const isValid = hex.length !== 0 && hex.length % 2 === 0 && !/[^a-fA-F0-9]/u.test(hex);
    if (!isValid) throw new Error('无效的十六进制字符串');

    const byteStrings = hex.match(/.{1,2}/g) ?? [];
    return Uint8Array.from(byteStrings.map((byte) => parseInt(byte, 16)));
};

/**
 * 将 UTF-8 字符串转换回 Uint8Array
 * - 查看定义:@see {@link utf8Tobytes}
 * @param {string} utf8String - UTF-8 编码的字符串
 * @returns {Uint8Array} 转换后的字节数组
 */
const utf8Tobytes = utf8String => {
    const encoder = new globalThis.TextEncoder();
    return encoder.encode(utf8String);
};

/**
 * 将 ASCII 字符串转换为 Uint8Array
 * - 查看定义:@see {@link asciiToBytes}
 * @param {string} value - ASCII 字符串
 * @returns {Uint8Array} 转换后的字节数组
 */
const asciiToBytes = value => {
    return Uint8Array.from(value.split('').map((x) => x.charCodeAt(0)));
};

/**
 * 将 Uint8Array 转换为十六进制字符串,替代 `Buffer.toString('hex')`;
 * - 查看定义:@see {@link toHex}
 * @param {Uint8Array} array - 要转换的字节数组
 * @returns {string} 十六进制字符串(小写)
 */
const toHex = array => {
    const hexParts = Array.from(array, (i) => i.toString(16).padStart(2, '0'));
    return hexParts.join(''); // adce000235bcc60a648b0b25f1f05503
};

/**
 * 创建一个 DataView,以便在解析 Uint8Array 的字节时可以灵活切分
 * - 查看定义:@see {@link toDataView}
 * @param {Uint8Array} array - 原始字节数组
 * @returns {DataView} 基于该数组的 DataView 视图
 */
const toDataView = array => {
    return new DataView(array.buffer, array.byteOffset, array.length);
};

/**
 * 将字节数组转换为 UTF-8 字符串
 * - 查看定义:@see {@link bytesToUtf8}
 * @param {Uint8Array} array - 要解码的字节数组
 * @returns {string} UTF-8 字符串
 */
const bytesToUtf8 = array => {
    const decoder = new globalThis.TextDecoder('utf-8');
    return decoder.decode(array);
};

/**
 * 确保两个 Uint8Array 深度相等
 * - 查看定义:@see {@link areEqual}
 * @param {Uint8Array} array1 - 第一个字节数组
 * @param {Uint8Array} array2 - 第二个字节数组
 * @returns {boolean} 是否相等
 */
const areEqual = (array1, array2) => {
    if (array1.length != array2.length) return false;
    return array1.every((val, i) => val === array2[i]);
};

/**
 * 将多个 Uint8Array 合并成一个 Uint8Array
 * - 查看定义:@see {@link concat}
 * @param {Uint8Array[]} arrays - 要合并的字节数组列表
 * @returns {Uint8Array} 合并后的新字节数组
 */
const concat = arrays => {
    let pointer = 0;
    const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0), toReturn = new Uint8Array(totalLength);
    arrays.forEach(arr => {
        toReturn.set(arr, pointer), pointer += arr.length;
    });
    return toReturn;
};

export { fromHex, utf8Tobytes, asciiToBytes, toHex, toDataView, bytesToUtf8, areEqual, concat };