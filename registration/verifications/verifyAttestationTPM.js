import { AsnParser } from '@peculiar/asn1-schema';
import {
    Certificate, id_ce_extKeyUsage, id_ce_subjectAltName, SubjectAlternativeName, ExtendedKeyUsage
} from '@peculiar/asn1-x509';
import {
    areEqual, concat, convertCertBufferToPEM, COSEKEYS, COSEALG, isCOSEAlg, isCOSEPublicKeyRSA, isCOSEPublicKeyEC2,
    decodeCredentialPublicKey, getCertificateInfo, toHash, validateCertificatePath,
    validateExtFIDOGenCEAAGUID, verifySignature
} from '../../helpers/index.js';
import { verifyAttestationWithMetadata, MetadataService } from '../../metadata/metadata.js';
import { TPM_ECC_CURVE_COSE_CRV_MAP, TPM_MANUFACTURERS, parseCertInfo, parsePubArea } from './tpm/index.js';

/**
 * 包含从 subjectAlternativeName 扩展中提取 TPM 特定值的逻辑
 */
const getTcgAtTpmValues = root => {
    const oidManufacturer = '2.23.133.2.1', oidModel = '2.23.133.2.2', oidVersion = '2.23.133.2.3';
    let tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion;

    /**
     * 遍历以下两种可能的结构:
     *
     * (符合规范的正常结构)
     * https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf (第33页)
     * Name [
     *   RelativeDistinguishedName [ AttributeTypeAndValue { type, value } ],
     *   RelativeDistinguishedName [ AttributeTypeAndValue { type, value } ],
     *   RelativeDistinguishedName [ AttributeTypeAndValue { type, value } ]
     * ]
     *
     * (不符合规范的非正常结构)
     * Name [
     *   RelativeDistinguishedName [
     *     AttributeTypeAndValue { type, value },
     *     AttributeTypeAndValue { type, value },
     *     AttributeTypeAndValue { type, value }
     *   ]
     * ]
     *
     * 两种结构在实际环境中都出现过,都需要支持
     */
    root.forEach(relName => {
        relName.forEach(attr => {
            if (attr.type === oidManufacturer) tcgAtTpmManufacturer = attr.value.toString();
            else if (attr.type === oidModel) tcgAtTpmModel = attr.value.toString();
            else if (attr.type === oidVersion) tcgAtTpmVersion = attr.value.toString();
        });
    });

    return { tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion };
},

    /**
     * 将 TPM 特定的 SHA 算法 ID 转换为 COSE 对应的算法 ID;
     * 注意:选择使用 ECDSA SHA ID 是任意的;在 `mapCoseAlgToWebCryptoAlg()` 中,
     * 任何能映射到 SHA-256 的 COSEALG 均可;
     *
     * SHA ID 参考自:
     * https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
     */
    attestedNameAlgToCOSEAlg = alg => {
        if (alg === 'TPM_ALG_SHA256') return COSEALG.ES256;
        else if (alg === 'TPM_ALG_SHA384') return COSEALG.ES384;
        else if (alg === 'TPM_ALG_SHA512') return COSEALG.ES512;
        throw new Error(`非预期的 TPM attested name 算法 ${alg}`);
    };

/**
 * 验证 TPM 认证器返回的 attestation 陈述,确保其符合 FIDO2 规范
 * - 查看定义:@see {@link verifyAttestationTPM}
 *
 * @param {Object} options - 验证所需的选项
 * @param {string} options.aaguid - 身份验证器的 AAGUID
 * @param {Map<string, unknown>} options.attStmt - attestation 陈述(包含 ver, sig, alg, x5c, pubArea, certInfo)
 * @param {BufferSource} options.authData - 认证器数据
 * @param {BufferSource} options.credentialPublicKey - 凭证公钥(COSE 编码)
 * @param {BufferSource} options.clientDataHash - 客户端数据的哈希值
 * @param {BufferSource[]} options.rootCertificates - 可选的根证书列表(用于证书链验证)
 * @returns {Promise<boolean>} 验证通过返回 true,否则抛出错误
 */
const verifyAttestationTPM = async options => {
    const { aaguid, attStmt, authData, credentialPublicKey, clientDataHash, rootCertificates } = options,
        ver = attStmt.get('ver'), sig = attStmt.get('sig'), alg = attStmt.get('alg'), x5c = attStmt.get('x5c'),
        pubArea = attStmt.get('pubArea'), certInfo = attStmt.get('certInfo');

    /**
     * 验证结构
     */
    if (ver !== '2.0') throw new Error(`非预期的 ver "${ver}",期望 "2.0" (TPM)`);
    if (!sig) throw new Error('attestation 语句中未提供 attestation 签名 (TPM)');
    if (!alg) throw new Error(`attestation 语句中未包含 alg (TPM)`);
    if (!isCOSEAlg(alg)) throw new Error(`attestation 语句包含无效的 alg ${alg} (TPM)`);
    if (!x5c) throw new Error('attestation 语句中未提供 attestation 证书 (TPM)');
    if (!pubArea) throw new Error('attestation 语句中未包含 pubArea (TPM)');
    if (!certInfo) throw new Error('attestation 语句中未包含 certInfo (TPM)');

    const parsedPubArea = parsePubArea(pubArea), { unique, type: pubType, parameters } = parsedPubArea,
        cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);

    // 验证 pubArea 的 parameters 和 unique 字段指定的公钥
    // 与 authenticatorData 中 attestedCredentialData 里的 credentialPublicKey 是否相同
    if (pubType === 'TPM_ALG_RSA') {
        if (!isCOSEPublicKeyRSA(cosePublicKey))
            throw new Error(`kty 为 ${cosePublicKey.get(COSEKEYS.kty)} 的凭证公钥与 ${pubType} 不匹配`);

        const n = cosePublicKey.get(COSEKEYS.n), e = cosePublicKey.get(COSEKEYS.e);
        if (!n) throw new Error('COSE 公钥缺少 n (TPM|RSA)');
        if (!e) throw new Error('COSE 公钥缺少 e (TPM|RSA)');
        if (!areEqual(unique, n)) throw new Error('PubArea.unique 与 credentialPublicKey 不相同 (TPM|RSA)');
        if (!parameters.rsa) throw new Error(`解析的 pubArea 类型为 RSA,但缺少 parameters.rsa (TPM|RSA)`);

        // 如果 exponent 等于 0x00,则 exponent 使用默认 RSA 指数 2^16+1 (65537)
        const eBuffer = e, pubAreaExponent = parameters.rsa.exponent || 65537,
            eSum = eBuffer[0] + (eBuffer[1] << 8) + (eBuffer[2] << 16); // 通过位运算得到整数值
        if (pubAreaExponent !== eSum) throw new Error(`非预期的公钥指数 ${eSum},期望 ${pubAreaExponent} (TPM|RSA)`);
    } else if (pubType === 'TPM_ALG_ECC') {
        if (!isCOSEPublicKeyEC2(cosePublicKey))
            throw new Error(`kty 为 ${cosePublicKey.get(COSEKEYS.kty)} 的凭证公钥与 ${pubType} 不匹配`);
        const crv = cosePublicKey.get(COSEKEYS.crv), x = cosePublicKey.get(COSEKEYS.x), y = cosePublicKey.get(COSEKEYS.y);
        if (!crv) throw new Error('COSE 公钥缺少 crv (TPM|ECC)');
        if (!x) throw new Error('COSE 公钥缺少 x (TPM|ECC)');
        if (!y) throw new Error('COSE 公钥缺少 y (TPM|ECC)');
        if (!areEqual(unique, concat([x, y])))
            throw new Error('PubArea.unique 与公钥 x 和 y 不相同 (TPM|ECC)');
        if (!parameters.ecc) throw new Error(`解析的 pubArea 类型为 ECC,但缺少 parameters.ecc (TPM|ECC)`);
        const pubAreaCurveID = parameters.ecc.curveID,
            pubAreaCurveIDMapToCOSECRV = TPM_ECC_CURVE_COSE_CRV_MAP[pubAreaCurveID];
        if (pubAreaCurveIDMapToCOSECRV !== crv)
            throw new Error(
                `公钥区域曲线 ID "${pubAreaCurveID}" 映射为 "${pubAreaCurveIDMapToCOSECRV}",` +
                `与公钥 crv "${crv}" 不匹配(TPM|ECC)`
            );
    }
    else throw new Error(`不支持的 pubArea.type "${pubType}"`);

    const parsedCertInfo = parseCertInfo(certInfo), { magic, type: certType, attested, extraData } = parsedCertInfo;
    if (magic !== 0xff544347) throw new Error(`非预期的 magic 值 "${magic}",期望 "0xff544347" (TPM)`);
    if (certType !== 'TPM_ST_ATTEST_CERTIFY')
        throw new Error(`非预期的 type "${certType}",期望 "TPM_ST_ATTEST_CERTIFY" (TPM)`);

    // 使用 attested 中的 nameAlg 对 pubArea 进行哈希,得到 pubAreaHash
    const pubAreaHash = await toHash(pubArea, attestedNameAlgToCOSEAlg(attested.nameAlg)),
        // 拼接 attested.nameAlg 和 pubAreaHash 得到 attestedName
        attestedName = concat([attested.nameAlgBuffer, pubAreaHash]);
    // 检查 certInfo.attested.name 是否等于 attestedName
    if (!areEqual(attested.name, attestedName)) throw new Error(`attested 名称比较失败 (TPM)`);

    // 拼接 authData 和 clientDataHash 得到 attToBeSigned
    const attToBeSigned = concat([authData, clientDataHash]),
        // 使用 attStmt.alg 指定的算法对 attToBeSigned 进行哈希,得到 attToBeSignedHash
        attToBeSignedHash = await toHash(attToBeSigned, alg);
    // 检查 certInfo.extraData 是否等于 attToBeSignedHash
    if (!areEqual(extraData, attToBeSignedHash))
        throw new Error('CertInfo.extraData 不等于哈希后的 attestation 数据 (TPM)');

    /**
     * 验证签名
     */
    if (x5c.length < 1) throw new Error('x5c 数组中不存在证书 (TPM)');

    // 取出 x5c 数组中的叶子 AIK 证书并解析
    const leafCertInfo = getCertificateInfo(x5c[0]),
        { basicConstraintsCA, version, subject, notAfter, notBefore } = leafCertInfo;
    if (basicConstraintsCA) throw new Error('证书的基本约束 CA 不是 `false` (TPM)');
    // 检查证书是否为版本 3(ASN.1 值必须为 2)
    if (version !== 2) throw new Error('证书版本不是 `3` (ASN.1 值为 2) (TPM)');
    // 检查主体(Subject)序列是否为空
    if (subject.combined.length > 0) throw new Error('证书主体(Subject)不为空 (TPM)');
    // 检查证书当前是否有效
    let now = new Date();
    if (notBefore > now) throw new Error(`证书在 "${notBefore.toString()}" 之后才生效 (TPM)`);
    // 检查证书是否过期
    now = new Date();
    if (notAfter < now) throw new Error(`证书在 "${notAfter.toString()}" 已过期 (TPM)`);

    /**
     * 深入解析证书 ASN.1 格式数据,获取需要验证的字段
     */
    const parsedCert = AsnParser.parse(x5c[0], Certificate);
    if (!parsedCert.tbsCertificate.extensions) throw new Error('证书缺少扩展字段 (TPM)');

    let subjectAltNamePresent, extKeyUsage;
    parsedCert.tbsCertificate.extensions.forEach(ext => {
        if (ext.extnID === id_ce_subjectAltName)
            subjectAltNamePresent = AsnParser.parse(ext.extnValue, SubjectAlternativeName);
        else if (ext.extnID === id_ce_extKeyUsage) extKeyUsage = AsnParser.parse(ext.extnValue, ExtendedKeyUsage);
    });

    // 检查证书是否包含 subjectAltName (2.5.29.17) 扩展
    if (!subjectAltNamePresent) throw new Error('证书未包含 subjectAltName 扩展 (TPM)');
    // TPM 特定值位于 directoryName 中,首先确保其中有值
    if (!subjectAltNamePresent[0].directoryName?.[0].length)
        throw new Error('证书 subjectAltName 扩展的 directoryName 为空 (TPM)');

    const { tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion } = getTcgAtTpmValues(
        subjectAltNamePresent[0].directoryName
    );

    if (!tcgAtTpmManufacturer || !tcgAtTpmModel || !tcgAtTpmVersion)
        throw new Error('证书包含不完整的 subjectAltName 数据 (TPM)');
    if (!extKeyUsage) throw new Error('证书未包含 ExtendedKeyUsage 扩展 (TPM)');

    // 检查 tcpaTpmManufacturer (2.23.133.2.1) 字段是否设置为有效的制造商 ID
    if (!TPM_MANUFACTURERS[tcgAtTpmManufacturer]) throw new Error(`无法匹配 TPM 制造商 "${tcgAtTpmManufacturer}" (TPM)`);

    // 检查证书包含 extKeyUsage (2.5.29.37) 扩展,并且必须包含 tcg-kp-AIKCertificate (2.23.133.8.3) OID
    if (extKeyUsage[0] !== '2.23.133.8.3')
        throw new Error(`非预期的 extKeyUsage "${extKeyUsage[0]}",期望 "2.23.133.8.3" (TPM)`);

    // 验证 attestation 语句中的 AAGUID 与叶子证书中的 AAGUID 是否匹配
    try {
        await validateExtFIDOGenCEAAGUID(parsedCert.tbsCertificate.extensions, aaguid);
    } catch (err) {
        throw new Error(`${err.message} (TPM)`);
    }

    // 如果该身份验证器存在元数据声明,则执行一些元数据检查
    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
        try {
            await verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg: alg });
        } catch (err) {
            throw new Error(`${err.message} (TPM)`);
        }
    } else {
        try {
            // 尝试使用通过 SettingsService 设置的根证书验证证书链
            await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
        } catch (err) {
            throw new Error(`${err.message} (TPM)`);
        }
    }

    // 使用从 AIK 证书中提取的公钥验证 certInfo 上的签名
    // 引用 Yuriy Ackermann 的话:"Get Martini friend, you are done!"
    return verifySignature({ signature: sig, data: certInfo, x509Certificate: x5c[0], hashAlgorithm: alg });
};

export { verifyAttestationTPM };