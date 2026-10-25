import { AsnParser, OctetString } from '@peculiar/asn1-schema';
import { areEqual, toHex } from './iso/index.js';

/**
 * attestation 证书扩展 OID:`id-fido-gen-ce-aaguid`
 *
 * 来源: [FIDO 规范文档][fido-att] 的「Verifying an Attestation Statement」章节
 * [fido-att]: https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html
 * @type {string}
 */
const id_fido_gen_ce_aaguid = '1.3.6.1.4.1.45724.1.1.4';

/**
 * 查找 id-fido-gen-ce-aaguid 证书扩展,如果存在,则将其与 attestation 语句中的 AAGUID 进行比较;
 * - 查看定义:@see {@link validateExtFIDOGenCEAAGUID}
 *
 * @param {Array<{ extnID: string, extnValue: ArrayBuffer }>} [certExtensions] - 证书扩展列表(可选)
 * @param {BufferSource} aaguid - attestation 语句中的 AAGUID 值
 * @returns {boolean} 验证通过时返回 true,否则抛出错误
 */
const validateExtFIDOGenCEAAGUID = (certExtensions, aaguid) => {
    if (!certExtensions) return true; // 证书没有扩展,无需验证

    const extFIDOGenCEAAGUID = certExtensions.find((ext) => ext.extnID === id_fido_gen_ce_aaguid);
    if (!extFIDOGenCEAAGUID) return true; // 扩展不存在,无需验证

    // 解析扩展值
    const parsedExtFIDOGenCEAAGUID = AsnParser.parse(extFIDOGenCEAAGUID.extnValue, OctetString),
        extValue = new Uint8Array(parsedExtFIDOGenCEAAGUID.buffer),
        aaguidAndExtAreEqual = areEqual(aaguid, extValue); // 比较两个值
    if (!aaguidAndExtAreEqual) {
        const _debugExtHex = toHex(extValue), _debugAAGUIDHex = toHex(aaguid);
        throw new Error(`证书扩展 id-fido-gen-ce-aaguid (${id_fido_gen_ce_aaguid}) 的值为 "${_debugExtHex}",
        但该扩展存在且与 attestation 语句中的 AAGUID 值 "${_debugAAGUIDHex}" 不相等`);
    }

    return true;
};

export { validateExtFIDOGenCEAAGUID };