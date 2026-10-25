import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { id_ce_keyDescription, KeyDescription } from '@peculiar/asn1-android';
import {
    areEqual, concat, convertCertBufferToPEM, convertCOSEtoPKCS, isCOSEAlg, validateCertificatePath, verifySignature
} from '../../helpers/index.js';
import { verifyAttestationWithMetadata, MetadataService } from '../../metadata/metadata.js';

/**
 * 验证格式为 'android-key' 的证明响应
 * - 查看定义:@see {@link verifyAttestationAndroidKey}
 *
 * @param {Object} options - 验证选项
 * @param {BufferSource} options.authData - 认证器数据(authenticatorData)
 * @param {BufferSource} options.clientDataHash - 客户端数据哈希值
 * @param {Map<string, any>} options.attStmt - 证明语句(attestation statement)
 * @param {BufferSource} options.credentialPublicKey - COSE 编码的凭证公钥
 * @param {BufferSource} options.aaguid - 认证器 AAGUID
 * @param {string[]} [options.rootCertificates] - 可选的信任根证书列表(PEM 格式)
 * @returns {Promise<boolean>} 验证通过时返回 true,否则抛出错误
 */
const verifyAttestationAndroidKey = async options => {
    const { authData, clientDataHash, attStmt, credentialPublicKey, aaguid, rootCertificates, } = options,
        x5c = attStmt.get('x5c'), sig = attStmt.get('sig'), alg = attStmt.get('alg');

    if (!x5c) throw new Error('在证明语句中未提供证明证书(Android Key)');
    if (!sig) throw new Error('在证明语句中未提供证明签名(Android Key)');
    if (!alg) throw new Error('证明语句未包含 alg(Android Key)');
    if (!isCOSEAlg(alg)) throw new Error(`证明语句包含无效的 alg ${alg}(Android Key)`);

    /**
     * 验证 x5c 中第一个证书的公钥与 authenticatorData 中 attestedCredentialData 内的 credentialPublicKey 是否匹配;
     */
    // 将证书中的公钥解析为 PKCS 格式
    const parsedCert = AsnParser.parse(x5c[0], Certificate),
        parsedCertPubKey = new Uint8Array(parsedCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey),
        credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey); // 将 credentialPublicKey 转换为 PKCS 格式
    if (!areEqual(credPubKeyPKCS, parsedCertPubKey))
        throw new Error('凭证公钥与叶子证书公钥不匹配(Android Key)');

    /**
     * 验证证明证书扩展数据中的 attestationChallenge 字段是否与 clientDataHash 相同;
     */
    // 在证书扩展中查找 Android KeyStore 扩展
    const extKeyStore = parsedCert.tbsCertificate.extensions?.find((ext) => ext.extnID === id_ce_keyDescription);
    if (!extKeyStore) throw new Error('证书未包含 extKeyStore 扩展(Android Key)');

    const parsedExtKeyStore = AsnParser.parse(extKeyStore.extnValue, KeyDescription),
        { attestationChallenge, teeEnforced, softwareEnforced } = parsedExtKeyStore;
    // 验证 extKeyStore 的值
    if (!areEqual(new Uint8Array(attestationChallenge.buffer), clientDataHash))
        throw new Error('证明挑战值与客户端数据哈希不相等(Android Key)');

    /**
     * AuthorizationList.allApplications 字段不应出现在任一授权列表(softwareEnforced 或 teeEnforced)中,
     * 因为 PublicKeyCredential 必须限定在 RP ID 范围内;
     *
     * (即这些列表中不应包含 [600] 标签)
     */
    if (teeEnforced.allApplications !== undefined)
        throw new Error('teeEnforced 包含了 "allApplications [600]" 标签(Android Key)');
    if (softwareEnforced.allApplications !== undefined)
        throw new Error('softwareEnforced 包含了 "allApplications [600]" 标签(Android Key)');

    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
        try {
            await verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg: alg });
        }
        catch (err) {
            throw new Error(`${err.message}(Android Key)`, { cause: err });
        }
    }
    else {
        /**
         * 验证 x5c 包含完整的证书链;
         */
        const x5cNoRootPEM = x5c.slice(0, -1).map(convertCertBufferToPEM),
            x5cRootPEM = x5c.slice(-1).map(convertCertBufferToPEM);
        try {
            await validateCertificatePath(x5cNoRootPEM, x5cRootPEM);
        }
        catch (err) {
            throw new Error(`${err.message}(Android Key)`, { cause: err });
        }

        /**
         * 确保根证书是 Google Hardware Attestation Root 证书之一
         *
         * https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
         */
        if (rootCertificates.length > 0 && rootCertificates.indexOf(x5cRootPEM[0]) < 0)
            throw new Error('x5c 根证书不是已知的根证书(Android Key)');
    }

    /**
     * 验证 sig 是对 authenticatorData 与 clientDataHash 的拼接结果的有效签名,
     * 使用 x5c 中第一个证书的公钥以及 alg 指定的算法;
     */
    const signatureBase = concat([authData, clientDataHash]);
    return verifySignature({ signature: sig, data: signatureBase, x509Certificate: x5c[0], hashAlgorithm: alg });
};

export { verifyAttestationAndroidKey };