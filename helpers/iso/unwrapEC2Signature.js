import { AsnParser } from '@peculiar/asn1-schema';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { COSECRV } from '../cose.js';
import { concat } from './isoUint8Array.js';

/**
 * 根据曲线类型返回 ECDSA 签名分量(r/s)的标准字节长度
 * @param {number} crv - COSE 曲线标识符(如 COSECRV.P256)
 * @returns {number} 签名分量的字节长度
 * @throws 当曲线类型不支持时抛出错误
 */
const getSignatureComponentLength = crv => {
    switch (crv) {
        case COSECRV.P256: return 32;
        case COSECRV.P384: return 48;
        case COSECRV.P521: return 66;
        default: throw new Error(`非预期的 COSE crv 值 ${crv} (EC2)`);
    }
},

    /**
     * 将 ASN.1 DER 编码的整数转换为 Web Crypto API 要求的固定长度字节序列
     * @type { (bytes: Uint8Array, componentLength: number) => Uint8Array }
     * @param {Uint8Array} bytes - DER 编码的整数(可能带有前导 0x00)
     * @param {number} componentLength - 目标长度(字节)
     * @returns {Uint8Array} 规范化后的固定长度字节序列
     * @throws 当输入字节长度无效时抛出错误
     */
    toNormalizedBytes = (bytes, componentLength) => {
        let normalizedBytes;
        // 如果字节长度短于预期,需要用前导 `0` 进行填充;
        if (bytes.length < componentLength)
            normalizedBytes = new Uint8Array(componentLength), normalizedBytes.set(bytes, componentLength - bytes.length);
        else if (bytes.length === componentLength) normalizedBytes = bytes;
        // 字节包含一个前导 `0` 用于表示该整数为正数;为了与 SubtleCrypto Web Crypto API 兼容,需要移除这个前导 `0`;
        else if (bytes.length === componentLength + 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0x80)
            normalizedBytes = bytes.subarray(1);
        else throw new Error(`无效的签名分量长度 ${bytes.length},期望为 ${componentLength}`);

        return normalizedBytes;
    };

/**
 * 从 COSE 结构的 EC2 签名(ASN.1 格式)中提取并规范化 r/s 值
 * - 查看定义:@see {@link unwrapEC2Signature}
 * @param {BufferSource} signature - ASN.1 编码的 ECDSA 签名(ECDSA-Sig-Value)
 * @param {number} crv - COSE 曲线标识符,用于确定分量长度
 * @returns {Uint8Array} 拼接后的规范化签名(r || s),长度为 2 * componentLength
 * @throws 当解析失败或分量长度无效时抛出错误
 */
const unwrapEC2Signature = (signature, crv) => {
    const parsedSignature = AsnParser.parse(signature, ECDSASigValue),
        rBytes = new Uint8Array(parsedSignature.r), sBytes = new Uint8Array(parsedSignature.s),
        componentLength = getSignatureComponentLength(crv),
        rNormalizedBytes = toNormalizedBytes(rBytes, componentLength),
        sNormalizedBytes = toNormalizedBytes(sBytes, componentLength),
        finalSignature = concat([rNormalizedBytes, sNormalizedBytes,]);
    return finalSignature;
};

export { unwrapEC2Signature };