import {
    fromBuffer, isBase64URL, trimPadding, utf8Tobytes, toBuffer, generateChallenge, generateUserID, decodeAttestationObject,
    parseAuthenticatorData, decodeCredentialPublicKey, COSEKEYS, getPassportClass, startPollingActivateScript,
    validateResponseStructure, parseAndValidateClientData, convertAAGUIDToString, parseBackupFlags, matchExpectedRPID, toHash
} from '../helpers/index.js';
import { SettingsService } from '../metadata/settings.js';
import {
    verifyAttestationFIDOU2F, verifyAttestationPacked, verifyAttestationAndroidSafetyNet,
    verifyAttestationAndroidKey, verifyAttestationApple, verifyAttestationTPM
} from './verifications/index.js';

/**
 * 支持的加密算法标识符（COSE 算法 ID）
 * - 参考: https://w3c.github.io/webauthn/#sctn-alg-identifier
 * - 参考: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 * @type {number[]}
 */
const supportedCOSEAlgorithmIdentifiers = [-8, -7, -36, -37, -38, -39, -257, -258, -259, -65535];

/**
 * 默认的身份验证器选择标准（符合 WebAuthn L2 规范）
 * @type {{ residentKey: ResidentKeyRequirement, userVerification: UserVerificationRequirement }}
 */
const defaultAuthenticatorSelection = { residentKey: 'preferred', userVerification: 'preferred' };

/**
 * 默认推荐的算法 ID 列表（优先使用 EdDSA, ES256, RS256）
 * @type {number[]}
 */
const defaultSupportedAlgorithmIDs = [-8, -7, -257];

/**
 * 使用 Windows Hello（Passport）进行原生注册,会直接在本地创建账户并获取公钥；
 * 仅在 Windows 环境且 `response.native === true` 时被调用；
 * @ignore
 * @param {Object} options - 内部参数
 * @param {Object} options.response - 浏览器返回的 Credential 对象（需包含 id）
 * @param {string|Buffer} options.expectedChallenge - 预期的挑战值（仅用于一致性检查）
 * @param {string} options.expectedOrigin - 预期的来源
 * @param {string} options.expectedRPID - 预期的 RP ID
 * @param {Function} options.PassportClass - 由 `getPassportClass` 返回的 Passport 类构造函数
 * @returns {Promise<{ verified: true, registrationInfo: Object }>}
 * @throws {Error} 如果账户创建失败或公钥获取失败
 */
const verifyRegistrationResponseNative = async options => {
    const { response, expectedChallenge, expectedOrigin, expectedRPID, PassportClass } = options,
        accountId = response.id;

    let stopPolling = null;
    try {
        stopPolling = startPollingActivateScript();
        const passport = new PassportClass(accountId);
        await passport.createAccount(0); // 0 = ReplaceExisting
        if (!passport.accountExists) throw new Error('账户创建失败');
        const publicKey = await passport.getPublicKey(1); // 1 = Pkcs1RsaPublicKey
        return {
            verified: true,
            registrationInfo: {
                fmt: 'none',
                aaguid: '00000000-0000-0000-0000-000000000000',
                credentialType: 'public-key',
                credential: { id: accountId, publicKey, counter: 0, transports: [] },
                attestationObject: Buffer.from([]),
                userVerified: true,
                credentialDeviceType: 'multiDevice',
                credentialBackedUp: false,
                origin: expectedOrigin,
                rpID: expectedRPID,
                authenticatorExtensionResults: {}
            },
        };
    } finally {
        if (stopPolling) stopPolling();
    }
};

/**
 * 生成用于 WebAuthn 注册的参数,可直接传递给 `navigator.credentials.create()`
 * - 查看定义: @see {@link generateRegistrationOptions}
 *
 * @param {Object} options - 配置选项
 * @param {string} options.rpName - 用户可见的、“友好”的网站/服务名称
 * @param {string} options.rpID - 有效的域名（`https://` 之后的部分）
 * @param {string} options.userName - 用户在此网站上的用户名（邮箱等）
 * @param {BufferSource} [options.userID] - 用户唯一标识符,默认生成随机值
 * @param {BufferSource | string} [options.challenge] - 随机挑战值,默认生成
 * @param {string} [options.userDisplayName] - 用户的显示名称,默认为 ""
 * @param {number} [options.timeout] - 超时毫秒数,默认 60000
 * @param {AttestationConveyancePreference} [options.attestationType] - 证明类型,默认 "none"
 * @param {PublicKeyCredentialDescriptor[]} [options.excludeCredentials] - 已注册凭证列表,防止重复注册
 * @param {AuthenticatorSelectionCriteria} [options.authenticatorSelection] - 限制验证器类型,
 * 默认 `{ residentKey: 'preferred', userVerification: 'preferred' }`
 * @param {AuthenticationExtensionsClientInputs} [options.extensions] - 扩展项
 * @param {number[]} [options.supportedAlgorithmIDs] - 支持的 COSE 算法 ID 数组,默认 `[-8, -7, -257]`
 * @param {'securityKey' | 'localDevice' | 'remoteDevice'} [options.preferredAuthenticatorType] - 提示注册特定类型的验证器
 * @returns {Promise<{
 *   challenge: string,
 *   rp: { name: string, id: string },
 *   user: { id: string, name: string, displayName: string },
 *   pubKeyCredParams: Array<{ alg: number, type: 'public-key' }>,
 *   timeout: number,
 *   attestation: AttestationConveyancePreference,
 *   excludeCredentials: PublicKeyCredentialDescriptor[],
 *   authenticatorSelection: AuthenticatorSelectionCriteria,
 *   extensions: AuthenticationExtensionsClientInputs,
 *   hints: string[]
 * }>}
 */
const generateRegistrationOptions = async options => {
    const {
        rpName, rpID, userName, userID, challenge = await generateChallenge(), userDisplayName = '', timeout = 60000,
        attestationType = 'none', excludeCredentials = [], authenticatorSelection = defaultAuthenticatorSelection,
        extensions, supportedAlgorithmIDs = defaultSupportedAlgorithmIDs, preferredAuthenticatorType,
    } = options, pubKeyCredParams = supportedAlgorithmIDs.map(id => ({ alg: id, type: 'public-key' }));

    if (authenticatorSelection.residentKey === undefined) {
        if (authenticatorSelection.requireResidentKey) authenticatorSelection.residentKey = 'required';
    }
    else authenticatorSelection.requireResidentKey = authenticatorSelection.residentKey === 'required';

    let _challenge = challenge;
    if (typeof _challenge === 'string') _challenge = utf8Tobytes(_challenge);
    if (typeof userID === 'string') throw new Error('不再支持使用字符串类型的 `userID`;');
    let _userID = userID;
    if (!_userID) _userID = await generateUserID();
    const hints = [];
    if (preferredAuthenticatorType) {
        if (preferredAuthenticatorType === 'securityKey')
            hints.push('security-key'), authenticatorSelection.authenticatorAttachment = 'cross-platform';
        else if (preferredAuthenticatorType === 'localDevice')
            hints.push('client-device'), authenticatorSelection.authenticatorAttachment = 'platform';
        else if (preferredAuthenticatorType === 'remoteDevice')
            hints.push('hybrid'), authenticatorSelection.authenticatorAttachment = 'cross-platform';
    }
    return {
        challenge: fromBuffer(_challenge),
        rp: { name: rpName, id: rpID },
        user: { id: fromBuffer(_userID), name: userName, displayName: userDisplayName },
        pubKeyCredParams,
        timeout,
        attestation: attestationType,
        excludeCredentials: excludeCredentials.map((cred) => {
            if (!isBase64URL(cred.id)) throw new Error(`excludeCredential 的 id “${cred.id}” 不是合法的 base64url 字符串`);
            return { ...cred, id: trimPadding(cred.id), type: 'public-key' };
        }),
        authenticatorSelection,
        extensions: { ...extensions, credProps: true }, hints
    };
};

/**
 * 验证用户是否合法完成了 WebAuthn 注册流程；
 * - 查看定义: @see {@link verifyRegistrationResponse}
 *
 * @param {Object} options - 验证选项
 * @param {Object} options.response - 由 `@flun/webauthn-browser` 的 `startRegistration()` 返回的响应对象
 * @param {string} options.response.id - 凭证 ID (base64url)
 * @param {string} options.response.rawId - 原始凭证 ID (base64url)
 * @param {string} options.response.type - 凭证类型 (应为 'public-key')
 * @param {Object} options.response.response - 证明响应数据
 * @param {string} options.response.response.clientDataJSON - base64url 编码的客户端数据
 * @param {string} options.response.response.attestationObject - base64url 编码的证明对象
 * @param {string[]} [options.response.response.transports] - 支持的传输方式列表
 * @param {boolean} [options.response.native] - 标记是否使用 Windows Hello 原生注册,默认为 false
 * @param {string|string[]|function} options.expectedChallenge - 预期的 challenge 值或自定义验证函数
 * @param {string|string[]} options.expectedOrigin - 期望的网站 URL（或 URL 数组）
 * @param {string|string[]} options.expectedRPID - 期望的 RP ID（或 ID 数组）
 * @param {string|string[]} [options.expectedType] - 期望的响应类型,默认为 'webauthn.create'
 * @param {boolean} [options.requireUserPresence] - 强制要求用户存在,默认为 true
 * @param {boolean} [options.requireUserVerification] - 强制要求用户验证,默认为 true
 * @param {number[]} [options.supportedAlgorithmIDs] - 支持的算法 ID 列表,默认为所有支持的算法
 * @param {boolean} [options.attestationSafetyNetEnforceCTSCheck] - SafetyNet 证明时要求 CTS 检查,默认为 true
 * @returns {Promise<{
 *   verified: boolean,
 *   registrationInfo?: {
 *     fmt: string,
 *     aaguid: string,
 *     credentialType: string,
 *     credential: { id: string, publicKey: BufferSource, counter: number, transports?: string[] },
 *     attestationObject: BufferSource,
 *     userVerified: boolean,
 *     credentialDeviceType: string,
 *     credentialBackedUp: boolean,
 *     origin: string,
 *     rpID: string,
 *     authenticatorExtensionResults: Record<string, unknown> | undefined,
 *   }
 * }>} 验证结果,若验证失败则返回 `{ verified: false }`
 */
const verifyRegistrationResponse = async options => {
    const {
        response, expectedChallenge, expectedOrigin, expectedRPID, expectedType, requireUserPresence = true,
        requireUserVerification = true, supportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers,
        attestationSafetyNetEnforceCTSCheck = true
    } = options, passportClass = getPassportClass('[reg]');

    if (!response?.id) throw new Error('缺少凭证 ID');
    if (passportClass && response.native === true) {
        try {
            return await verifyRegistrationResponseNative({
                response, expectedChallenge, expectedOrigin, expectedRPID, PassportClass: passportClass
            });
        } catch (err) {
            throw new Error(`Windows Hello 原生注册失败: ${err.message}`);
        }
    }
    validateResponseStructure(response);
    const { response: attestationResponse } = response, clientData = await parseAndValidateClientData(
        attestationResponse.clientDataJSON, expectedType || 'webauthn.create', expectedChallenge, expectedOrigin
    ), attestationObject = toBuffer(attestationResponse.attestationObject),
        decodedAttestationObject = decodeAttestationObject(attestationObject),
        fmt = decodedAttestationObject.get('fmt'), authData = decodedAttestationObject.get('authData'),
        attStmt = decodedAttestationObject.get('attStmt'), parsedAuthData = parseAuthenticatorData(authData),
        { aaguid, rpIdHash, flags, credentialID, counter, credentialPublicKey, extensionsData } = parsedAuthData;
    let matchedRPID;

    if (expectedRPID) {
        let expectedRPIDs = [];
        if (typeof expectedRPID === 'string') expectedRPIDs = [expectedRPID];
        else expectedRPIDs = expectedRPID;
        matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
    }
    if (requireUserPresence && !flags.up) throw new Error('要求用户存在,但找不到用户');
    if (requireUserVerification && !flags.uv) throw new Error('要求用户验证,但无法强制执行');
    if (!credentialID) throw new Error('身份验证器未提供凭证 ID');
    if (!credentialPublicKey) throw new Error('身份验证器未提供公钥');
    if (!aaguid) throw new Error('注册过程中未提供 AAGUID');
    const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey), alg = decodedPublicKey.get(COSEKEYS.alg);
    if (typeof alg !== 'number') throw new Error('凭证公钥缺少数值类型的 alg');
    if (!supportedAlgorithmIDs.includes(alg)) {
        const supported = supportedAlgorithmIDs.join(', ');
        throw new Error(`意外的公钥 alg "${alg}",期望为以下之一："${supported}"`);
    }
    const clientDataHash = await toHash(toBuffer(attestationResponse.clientDataJSON)),
        rootCertificates = SettingsService.getRootCertificates({ identifier: fmt }),
        verifierOpts = {
            aaguid, attStmt, authData, clientDataHash, credentialID, credentialPublicKey, rootCertificates, rpIdHash,
            attestationSafetyNetEnforceCTSCheck
        };
    let verified = false;
    if (fmt === 'fido-u2f') verified = await verifyAttestationFIDOU2F(verifierOpts);
    else if (fmt === 'packed') verified = await verifyAttestationPacked(verifierOpts);
    else if (fmt === 'android-safetynet') verified = await verifyAttestationAndroidSafetyNet(verifierOpts);
    else if (fmt === 'android-key') verified = await verifyAttestationAndroidKey(verifierOpts);
    else if (fmt === 'tpm') verified = await verifyAttestationTPM(verifierOpts);
    else if (fmt === 'apple') verified = await verifyAttestationApple(verifierOpts);
    else if (fmt === 'none') {
        if (attStmt.size > 0) throw new Error('None 证明存在意外的证明语句');
        verified = true;
    }
    else throw new Error(`不支持的证明格式：${fmt}`);
    if (!verified) return { verified: false };

    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);
    return {
        verified: true,
        registrationInfo: {
            fmt,
            aaguid: convertAAGUIDToString(aaguid),
            credentialType: 'public-key',
            credential: {
                id: fromBuffer(credentialID),
                publicKey: credentialPublicKey,
                counter,
                transports: response.response.transports,
            },
            attestationObject,
            userVerified: flags.uv,
            credentialDeviceType,
            credentialBackedUp,
            origin: clientData.origin,
            rpID: matchedRPID,
            authenticatorExtensionResults: extensionsData,
        }
    };
};

export { supportedCOSEAlgorithmIdentifiers, generateRegistrationOptions, verifyRegistrationResponse };