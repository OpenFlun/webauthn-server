import {
    concat, convertCertBufferToPEM, isCOSEAlg, getCertificateInfo, validateCertificatePath, validateExtFIDOGenCEAAGUID,
    verifySignature
} from '../../helpers/index.js';
import { verifyAttestationWithMetadata, MetadataService } from '../../metadata/metadata.js';

/**
 * 验证格式为 'packed' 的 attestation 响应
 * - 查看定义:@see {@link verifyAttestationPacked}
 *
 * @param {Object} options - 验证选项
 * @param {Map<number, BufferSource>} options.attStmt - attestation 语句的原始 Map
 * @param {BufferSource} options.authData - 认证器数据
 * @param {BufferSource} options.clientDataHash - 客户端数据的 SHA-256 哈希
 * @param {BufferSource} options.credentialPublicKey - COSE 编码的凭证公钥
 * @param {BufferSource} options.aaguid - 认证器 Attestation GUID
 * @param {string[]} [options.rootCertificates] - PEM 格式的可信根证书列表
 * @returns {Promise<boolean>} 验证通过时返回 true,否则抛出错误
 */
const verifyAttestationPacked = async options => {
    const { attStmt, clientDataHash, authData, credentialPublicKey, aaguid, rootCertificates, } = options,
        sig = attStmt.get('sig'), x5c = attStmt.get('x5c'), alg = attStmt.get('alg');

    if (!sig) throw new Error('attestation 语句中未提供签名 (Packed)');
    if (!alg) throw new Error('attestation 语句中未包含 alg (Packed)');
    if (!isCOSEAlg(alg)) throw new Error(`attestation 语句包含无效的 alg ${alg} (Packed)`);

    const signatureBase = concat([authData, clientDataHash]);
    let verified = false;

    if (x5c) {
        const { subject, basicConstraintsCA, version, notBefore, notAfter, parsedCertificate } =
            getCertificateInfo(x5c[0]),
            { OU, CN, O, C } = subject;

        if (OU !== 'Authenticator Attestation') throw new Error('证书 OU 不是 "Authenticator Attestation" (Packed|Full)');
        if (!CN) throw new Error('证书 CN 为空 (Packed|Full)');
        if (!O) throw new Error('证书 O 为空 (Packed|Full)');
        if (!C || C.length !== 2) throw new Error('证书 C 不是两位 ISO 3166 国家代码 (Packed|Full)');
        if (basicConstraintsCA) throw new Error('证书的基本约束 CA 不为 `false` (Packed|Full)');
        if (version !== 2) throw new Error('证书版本不是 `3`(ASN.1 值为 2)(Packed|Full)');

        let now = new Date();
        if (notBefore > now) throw new Error(`证书在 "${notBefore.toString()}" 之前无效 (Packed|Full)`);
        now = new Date();
        if (notAfter < now) throw new Error(`证书在 "${notAfter.toString()}" 之后已过期 (Packed|Full)`);

        // 根据叶子证书中的 AAGUID 验证 attestation 语句的 AAGUID
        try {
            await validateExtFIDOGenCEAAGUID(parsedCertificate.tbsCertificate.extensions, aaguid);
        } catch (err) {
            throw new Error(`${err.message} (Packed|Full)`);
        }

        // 如果可用,使用 metadata 语句中的信息验证 attestation alg 和 x5c
        const statement = await MetadataService.getStatement(aaguid);
        if (statement) {
            // x5c 的存在意味着这是一个完整 attestation;检查 attestationTypes 是否包含 packed attestations
            if (statement.attestationTypes.indexOf('basic_full') < 0)
                throw new Error('元数据中未指示支持完整 attestation (Packed|Full)');
            try {
                await verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg: alg });
            } catch (err) {
                throw new Error(`${err.message} (Packed|Full)`);
            }
        } else {
            try {
                // 尝试使用通过 SettingsService 设置的根证书验证证书链
                await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
            } catch (err) {
                throw new Error(`${err.message} (Packed|Full)`);
            }
        }

        verified = await verifySignature({ signature: sig, data: signatureBase, x509Certificate: x5c[0] });
    }
    else verified = await verifySignature({
        signature: sig, data: signatureBase, credentialPublicKey, hashAlgorithm: alg
    });

    return verified;
};

export { verifyAttestationPacked };