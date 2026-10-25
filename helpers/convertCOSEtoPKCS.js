import { decodeFirst, concat } from './iso/index.js';
import { COSEKEYS } from './cose.js';

/**
 * 将 COSE 编码的公钥转换为 PKCS 密钥
 * - 查看定义:@see {@link convertCOSEtoPKCS}
 * @param {BufferSource} cosePublicKey - COSE 编码的公钥数据
 * @returns {Uint8Array} PKCS 格式的公钥字节序列(未压缩点格式,04 || x || y 或 04 || x)
 */
const convertCOSEtoPKCS = cosePublicKey => {
    // 这里处理得有些粗糙,使用了 COSEPublicKeyEC2,因为它可能同时包含 x 和 y;
    // 但当没有 y 时,它更适合被类型化为 COSEPublicKeyOKP,暂时保留这样,
    // 如果以后真的成为问题再重新处理;
    const struct = decodeFirst(cosePublicKey), tag = Uint8Array.from([0x04]),
        x = struct.get(COSEKEYS.x), y = struct.get(COSEKEYS.y);

    if (!x) throw new Error('COSE 公钥缺少 x');
    if (y) return concat([tag, x, y]);

    return concat([tag, x]);
};

export { convertCOSEtoPKCS };