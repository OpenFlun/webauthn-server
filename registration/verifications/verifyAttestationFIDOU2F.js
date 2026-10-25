import { concat, convertCOSEtoPKCS, convertCertBufferToPEM, COSEALG, toHex, validateCertificatePath, verifySignature }
    from '../../helpers/index.js';

/**
 * 验证格式为 'fido-u2f' 的认证声明
 * - 查看定义:@see {@link verifyAttestationFIDOU2F}
 *
 * @param {Object} options - 验证配置选项
 * @param {Map<number, BufferSource>} options.attStmt - attestation 声明数据 Map
 * @param {BufferSource} options.clientDataHash - 客户端数据哈希
 * @param {BufferSource} options.rpIdHash - 依赖方 ID 哈希
 * @param {BufferSource} options.credentialID - 凭证 ID
 * @param {BufferSource} options.credentialPublicKey - 凭证公钥(COSE 编码)
 * @param {BufferSource} options.aaguid - 认证器 AAGUID
 * @param {BufferSource[]} [options.rootCertificates] - 根证书列表(PEM 格式)
 * @returns {Promise<boolean>} 验证通过返回 true,否则抛出错误
 */
const verifyAttestationFIDOU2F = async options => {
    const { attStmt, clientDataHash, rpIdHash, credentialID, credentialPublicKey, aaguid, rootCertificates } = options,
        reservedByte = Uint8Array.from([0x00]), publicKey = convertCOSEtoPKCS(credentialPublicKey),
        signatureBase = concat([reservedByte, rpIdHash, clientDataHash, credentialID, publicKey]),
        sig = attStmt.get('sig'), x5c = attStmt.get('x5c');

    if (!x5c) throw new Error('认证声明中未提供认证证书 (FIDOU2F)');
    if (!sig) throw new Error('认证声明中未提供认证签名 (FIDOU2F)');

    // FIDO 规范要求 aaguid 必须等于 0x00 才是合法的
    const aaguidToHex = Number.parseInt(toHex(aaguid), 16);
    if (aaguidToHex !== 0x00) throw new Error(`AAGUID "${aaguidToHex}" 不符合预期值`);

    try {
        // 尝试使用通过 SettingsService 设置的根证书验证证书链
        await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
    } catch (err) {
        throw new Error(`${err.message} (FIDOU2F)`);
    }

    return verifySignature({ signature: sig, data: signatureBase, x509Certificate: x5c[0], hashAlgorithm: COSEALG.ES256 });
};

export { verifyAttestationFIDOU2F };