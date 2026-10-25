import { TPM_ALG, TPM_ST, TPM_ECC_CURVE } from './constants.js';
import { toDataView, concat } from '../../../helpers/index.js';

// ================================= parseCertInfo函数 =================================
/**
 * 将 TPM 认证信息(certInfo)解析为可读的结构化数据
 * - 查看定义:@see {@link parseCertInfo}
 *
 * @param {BufferSource} certInfo - 原始的 TPM 认证信息(certInfo)字节数据
 * @returns {{
 *   magic: number,
 *   type: string,
 *   qualifiedSigner: Uint8Array,
 *   extraData: Uint8Array,
 *   clockInfo: { clock: Uint8Array, resetCount: number, restartCount: number, safe: boolean },
 *   firmwareVersion: Uint8Array,
 *   attested: {
 *     nameAlg: string,
 *     nameAlgBuffer: Uint8Array,
 *     name: Uint8Array,
 *     qualifiedName: Uint8Array
 *   }
 * }} 解析后的结构化认证信息对象
 */
const parseCertInfo = certInfo => {
    let pointer = 0;
    // 获取魔数常量
    const dataView = toDataView(certInfo), magic = dataView.getUint32(pointer);
    pointer += 4;

    // 确定认证所使用的算法
    const typeBuffer = dataView.getUint16(pointer);
    pointer += 2;
    // 父实体的名称,可忽略
    const type = TPM_ST[typeBuffer], qualifiedSignerLength = dataView.getUint16(pointer);
    pointer += 2;
    const qualifiedSigner = certInfo.slice(pointer, pointer += qualifiedSignerLength),
        // 获取 `attsToBeSigned` 的期望哈希值
        extraDataLength = dataView.getUint16(pointer);
    pointer += 2;
    const extraData = certInfo.slice(pointer, pointer += extraDataLength),
        // 关于 TPM 设备内部时钟的信息,可忽略
        clock = certInfo.slice(pointer, pointer += 8), resetCount = dataView.getUint32(pointer);
    pointer += 4;
    const restartCount = dataView.getUint32(pointer);
    pointer += 4;
    const safe = !!certInfo.slice(pointer, pointer += 1), clockInfo = { clock, resetCount, restartCount, safe },
        // TPM 设备固件版本,被认证的名称
        firmwareVersion = certInfo.slice(pointer, pointer += 8), attestedNameLength = dataView.getUint16(pointer);
    pointer += 2;
    const attestedName = certInfo.slice(pointer, pointer += attestedNameLength),
        attestedNameDataView = toDataView(attestedName),
        qualifiedNameLength = dataView.getUint16(pointer); // 被认证的限定名称,可忽略
    pointer += 2;
    const qualifiedName = certInfo.slice(pointer, pointer += qualifiedNameLength),
        attested = {
            nameAlg: TPM_ALG[attestedNameDataView.getUint16(0)],
            nameAlgBuffer: attestedName.slice(0, 2),
            name: attestedName,
            qualifiedName,
        };

    return { magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested };
};

// ================================= parsePubArea函数 =================================


/**
 * 解析 TPM 证明中的 pubArea 缓冲区
 * - 查看定义:@see {@link parsePubArea}
 * - 参考规范 12.2.4 TPMT_PUBLIC:
 * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
 *
 * @param {BufferSource} pubArea - 包含 TPMT_PUBLIC 结构的原始字节缓冲区
 * @returns {{
 *   type: string,
 *   nameAlg: string,
 *   objectAttributes: {
 *     fixedTPM: boolean,
 *     stClear: boolean,
 *     fixedParent: boolean,
 *     sensitiveDataOrigin: boolean,
 *     userWithAuth: boolean,
 *     adminWithPolicy: boolean,
 *     noDA: boolean,
 *     encryptedDuplication: boolean,
 *     restricted: boolean,
 *     decrypt: boolean,
 *     signOrEncrypt: boolean
 *   },
 *   authPolicy: Uint8Array,
 *   parameters: {
 *     rsa?: { symmetric: string, scheme: string, keyBits: number, exponent: number },
 *     ecc?: { symmetric: string, scheme: string, curveID: string, kdf: string }
 *   },
 *   unique: Uint8Array
 * }} 解析后的公钥区域结构
 */
const parsePubArea = pubArea => {
    let pointer = 0;
    const dataView = toDataView(pubArea), type = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    const nameAlg = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    // 获取一些身份验证器的属性(?)
    // const objectAttributesInt = pubArea.slice(pointer, (pointer += 4)).readUInt32BE(0);
    const objectAttributesInt = dataView.getUint32(pointer);
    pointer += 4;
    const objectAttributes = {
        fixedTPM: !!(objectAttributesInt & 1),
        stClear: !!(objectAttributesInt & 2),
        fixedParent: !!(objectAttributesInt & 8),
        sensitiveDataOrigin: !!(objectAttributesInt & 16),
        userWithAuth: !!(objectAttributesInt & 32),
        adminWithPolicy: !!(objectAttributesInt & 64),
        noDA: !!(objectAttributesInt & 512),
        encryptedDuplication: !!(objectAttributesInt & 1024),
        restricted: !!(objectAttributesInt & 32768),
        decrypt: !!(objectAttributesInt & 65536),
        signOrEncrypt: !!(objectAttributesInt & 131072),
    };

    // 切出动态长度的 authPolicy
    const authPolicyLength = dataView.getUint16(pointer);
    pointer += 2;
    const authPolicy = pubArea.slice(pointer, pointer += authPolicyLength), parameters = {};
    // 根据类型提取额外的曲线参数
    let unique = Uint8Array.from([]);
    if (type === 'TPM_ALG_RSA') {
        const symmetric = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const scheme = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const keyBits = dataView.getUint16(pointer);
        pointer += 2;
        const exponent = dataView.getUint32(pointer);
        pointer += 4, parameters.rsa = { symmetric, scheme, keyBits, exponent };

        /**
         * 参考规范 11.2.4.5 TPM2B_PUBLIC_KEY_RSA:
         * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
         */
        // const uniqueLength = pubArea.slice(pointer, (pointer += 2)).readUInt16BE(0);
        const uniqueLength = dataView.getUint16(pointer);
        pointer += 2, unique = pubArea.slice(pointer, pointer += uniqueLength);
    } else if (type === 'TPM_ALG_ECC') {
        const symmetric = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const scheme = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const curveID = TPM_ECC_CURVE[dataView.getUint16(pointer)];
        pointer += 2;
        const kdf = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 4;

        parameters.ecc = { symmetric, scheme, curveID, kdf };

        /**
         * 参考规范 11.2.5.1 TPM2B_ECC_PARAMETER:
         * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
         */
        // 获取 X
        const uniqueXLength = dataView.getUint16(pointer);
        pointer += 2;
        // 获取 Y
        const uniqueX = pubArea.slice(pointer, pointer += uniqueXLength), uniqueYLength = dataView.getUint16(pointer);
        pointer += 2;
        const uniqueY = pubArea.slice(pointer, pointer += uniqueYLength);
        unique = concat([uniqueX, uniqueY]);
    } else {
        throw new Error(`非预期的类型 "${type}" (TPM)`);
    }

    return { type, nameAlg, objectAttributes, authPolicy, parameters, unique };
};

export { parseCertInfo, parsePubArea };