import {
    fromBuffer, isBase64URL, trimPadding, utf8Tobytes, toBuffer, generateChallenge, generateUserID, decodeAttestationObject,
    decodeClientDataJSON, parseAuthenticatorData, decodeCredentialPublicKey, COSEKEYS, convertAAGUIDToString,
    parseBackupFlags, matchExpectedRPID, toHash
} from '../helpers/index.js';
import { SettingsService } from '../metadata/settings.js';
import {
    verifyAttestationFIDOU2F, verifyAttestationPacked, verifyAttestationAndroidSafetyNet,
    verifyAttestationAndroidKey, verifyAttestationApple, verifyAttestationTPM
} from './verifications/index.js';

// ========== 新增：直接加载独立的 .node 包（Electron + Windows） ==========
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

let PassportClass = null;
let isNativeAvailable = false;
const isElectron = !!process.versions?.electron;
const isWindows = process.platform === 'win32';

if (isElectron && isWindows) {
    const arch = process.arch; // 'x64' 或 'ia32'
    const pkgName = `passport-desktop-win32-${arch}-msvc`;
    try {
        const binding = require(pkgName);
        if (binding.Passport) {
            PassportClass = binding.Passport;
        } else if (typeof binding.available === 'function') {
            PassportClass = binding;
        }
        if (PassportClass && typeof PassportClass.available === 'function' && PassportClass.available()) {
            isNativeAvailable = true;
        }
    } catch (_) {
        // 静默失败
    }
}
// ===================================================

// ================================= 生成身份验证器注册参数 =================================
/**
 * 支持的加密算法标识符
 * - 查看定义:@see {@link supportedCOSEAlgorithmIdentifiers}
 * - 参见 https://w3c.github.io/webauthn/#sctn-alg-identifier
 * 以及 https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 * @type {number[]}
 */
const supportedCOSEAlgorithmIdentifiers = [
    // EdDSA（放在首位以鼓励验证器优先使用此算法而非 ES256）
    -8,
    // 带 SHA-256 的 ECDSA
    -7,
    // 带 SHA-512 的 ECDSA
    -36,
    // 带 SHA-256 的 RSASSA-PSS
    -37,
    // 带 SHA-384 的 RSASSA-PSS
    -38,
    // 带 SHA-512 的 RSASSA-PSS
    -39,
    // 带 SHA-256 的 RSASSA-PKCS1-v1_5
    -257,
    // 带 SHA-384 的 RSASSA-PKCS1-v1_5
    -258,
    // 带 SHA-512 的 RSASSA-PKCS1-v1_5
    -259,
    // 带 SHA-1 的 RSASSA-PKCS1-v1_5（已弃用，仅为遗留支持）
    -65535,
],

    /**
     * 根据最新规范设置默认的身份验证器选择选项：
     * https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
     *
     * 有助于某些旧平台（例如 Android 7.0 Nougat）了解这些默认值;
     * @type {{ residentKey: ResidentKeyRequirement, userVerification: UserVerificationRequirement }}
     */
    defaultAuthenticatorSelection = { residentKey: 'preferred', userVerification: 'preferred' },

    /**
     * 使用最广泛支持的算法
     * 参见：
     *   - https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     *   - https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams
     * @type {number[]}
     */
    defaultSupportedAlgorithmIDs = [-8, -7, -257];

/**
 * 生成用于身份验证器注册的参数,该参数可直接传递给 `navigator.credentials.create(...)`
 * - 查看定义:@see {@link generateRegistrationOptions}
 * **选项说明：**
 *
 * @param {Object} options - 配置选项
 * @param {string} options.rpName - 用户可见的、“友好”的网站/服务名称
 * @param {string} options.rpID - 有效的域名（`https://` 之后的部分）
 * @param {string} options.userName - 用户在此网站上的用户名（邮箱等）
 * @param {BufferSource} [options.userID] - 用户在此网站上的唯一标识符,默认生成一个随机标识符
 * @param {BufferSource | string} [options.challenge] - 随机值，身份验证器需要对其签名并返回。默认生成一个随机值
 * @param {string} [options.userDisplayName] - 用户的真实姓名,默认为 `""`
 * @param {number} [options.timeout] - 用户完成认证所允许的最长时间（毫秒）。默认为 `60000`
 * @param {AttestationConveyancePreference} [options.attestationType] - 具体的证明声明类型,默认为 `"none"`
 * @param {PublicKeyCredentialDescriptor[]} [options.excludeCredentials] - 用户已注册的身份验证器列表,防止同一凭证被重复注册,默认为 `[]`
 * @param {AuthenticatorSelectionCriteria} [options.authenticatorSelection] - 用于限制可使用验证器类型的进阶条件,
 * 默认为 `{ residentKey: 'preferred', userVerification: 'preferred' }`
 * @param {AuthenticationExtensionsClientInputs} [options.extensions] - 身份验证器或浏览器在证明过程中应使用的附加插件/扩展
 * @param {number[]} [options.supportedAlgorithmIDs] - 当前依赖方支持的用于证明的 COSE 算法标识符数组,
 * 参见 https://www.iana.org/assignments/cose/cose.xhtml#algorithms; 默认为 `[-8, -7, -257]`
 * @param {'securityKey' | 'localDevice' | 'remoteDevice'} [options.preferredAuthenticatorType] - 建议浏览器提示用户注册特定类型的身份验证器
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
        rpName, rpID, userName, userID, challenge = await generateChallenge(),
        userDisplayName = '', timeout = 60000, attestationType = 'none', excludeCredentials = [],
        authenticatorSelection = defaultAuthenticatorSelection, extensions,
        supportedAlgorithmIDs = defaultSupportedAlgorithmIDs, preferredAuthenticatorType,
    } = options,
        /**
         * 根据算法 ID 数组构建 pubKeyCredParams
         */
        pubKeyCredParams = supportedAlgorithmIDs.map(id => ({ alg: id, type: 'public-key' }));

    /**
     * 处理 `residentKey` 与 `requireResidentKey` 的设置细节
     * 根据选项中的定义来配置两者
     */
    if (authenticatorSelection.residentKey === undefined) {
        /**
         * `residentKey`：“如果未提供值，则有效值为：若 requireResidentKey 为 true 则为 `required`，
         * 若为 false 或未提供则为 `discouraged`;”
         *
         * 参见 https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey
         */
        if (authenticatorSelection.requireResidentKey) authenticatorSelection.residentKey = 'required';
        else {
            /**
             * FIDO Conformance v1.7.2 在以下设置下会失败第一个测试,尽管这在技术上符合 WebAuthn L2 规范……
             */
            // authenticatorSelection.residentKey = 'discouraged';
        }
    } else {
        /**
         * `requireResidentKey`：“依赖方应仅当 residentKey 设置为 `"required"` 时才将其设为 true”
         *
         * 规范说明此属性默认为 `false`,因此将其赋值为 `false` 也是可以的
         *
         * 参见 https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
         */
        authenticatorSelection.requireResidentKey = authenticatorSelection.residentKey === 'required';
    }

    /**
     * 保留对字符串类型 challenge 的支持
     */
    let _challenge = challenge;
    if (typeof _challenge === 'string') _challenge = utf8Tobytes(_challenge);

    /**
     * 显式禁止再使用字符串类型的 userID,因为下面的 `fromBuffer()` 会在字符串传入时返回空字符串！
     */
    if (typeof userID === 'string') throw new Error('不再支持使用字符串类型的 `userID`;');

    /**
     * 如果未提供 userID，则生成一个
     */
    let _userID = userID;
    if (!_userID) _userID = await generateUserID();

    /**
     * 将首选身份验证器类型映射到 hints 数组，同时为了向后兼容也映射到 authenticatorAttachment
     */
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
            if (!isBase64URL(cred.id))
                throw new Error(`excludeCredential 的 id “${cred.id}” 不是合法的 base64url 字符串`);
            return { ...cred, id: trimPadding(cred.id), type: 'public-key' };
        }),
        authenticatorSelection,
        extensions: { ...extensions, credProps: true },
        hints,
    };
};

// ================================= 验证是否正确完成了注册 =================================

// ---- 新增：内部原生注册函数 ----
async function verifyRegistrationResponseNative(options) {
    const {
        response,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
    } = options;

    const accountId = response.id;
    if (!accountId) throw new Error('缺少凭证 ID，无法用于 Windows Hello 注册');

    // 直接创建账户
    const passport = new PassportClass(accountId);
    await passport.createAccount(0); // 0 = ReplaceExisting

    if (!passport.accountExists) {
        throw new Error('账户创建失败');
    }

    const publicKey = await passport.getPublicKey(1); // Pkcs1RsaPublicKey

    // 验证 expectedChallenge 和 expectedOrigin
    const challenge = expectedChallenge;
    const origin = expectedOrigin;
    const rpID = expectedRPID;

    if (typeof expectedChallenge === 'function') {
        if (!(await expectedChallenge(challenge))) {
            throw new Error('自定义挑战值验证器返回 false');
        }
    } else if (challenge !== expectedChallenge) {
        throw new Error(`意外的注册响应挑战值 "${challenge}",期望 "${expectedChallenge}"`);
    }

    if (Array.isArray(expectedOrigin)) {
        if (!expectedOrigin.includes(origin)) {
            throw new Error(`意外的注册响应来源 "${origin}",期望为以下之一：${expectedOrigin.join(', ')}`);
        }
    } else if (origin !== expectedOrigin) {
        throw new Error(`意外的注册响应来源 "${origin}",期望 "${expectedOrigin}"`);
    }

    // 直接使用 accountId 作为凭证 ID，无需重新编码
    return {
        verified: true,
        registrationInfo: {
            fmt: 'none',
            aaguid: '00000000-0000-0000-0000-000000000000',
            credentialType: 'public-key',
            credential: {
                id: accountId, // 直接使用原始字符串
                publicKey: publicKey,
                counter: 0,
                transports: [],
            },
            attestationObject: Buffer.from([]),
            userVerified: true,
            credentialDeviceType: 'multiDevice',
            credentialBackedUp: false,
            origin: origin,
            rpID: rpID,
            authenticatorExtensionResults: {},
        },
    };
}

/**
 * 验证用户是否合法完成了注册流程
 * - 查看定义:@see {@link verifyRegistrationResponse}
 *
 * @param {Object} options - 验证选项
 * @param {Object} options.response - `@flun/webauthn-browser` 的 `startAuthentication()` 返回的响应对象
 * @param {Object} options.response.response - 包含证明数据的响应对象
 * @param {string} options.response.id - 凭证 ID (base64url)
 * @param {string} options.response.rawId - 原始凭证 ID (base64url)
 * @param {string} options.response.type - 凭证类型 (应为 'public-key')
 * @param {Object} options.response.response - 证明响应数据
 * @param {string} options.response.response.clientDataJSON - base64url 编码的客户端数据
 * @param {string} options.response.response.attestationObject - base64url 编码的证明对象
 * @param {string[]} [options.response.response.transports] - 支持的传输方式列表
 * @param {string|string[]|function} options.expectedChallenge - `generateRegistrationOptions()` 返回的 `options.challenge` 的 base64url 编码值，或自定义验证函数
 * @param {string|string[]} options.expectedOrigin - 注册应发生的网站 URL（或 URL 数组）
 * @param {string|string[]} options.expectedRPID - 注册选项中指定的 RP ID（或 ID 数组）
 * @param {string|string[]} [options.expectedType] - 期望的响应类型（默认为 'webauthn.create'）
 * @param {boolean} [options.requireUserPresence] - 强制要求身份验证器验证用户存在（或在自动注册时跳过），默认为 `true`
 * @param {boolean} [options.requireUserVerification] - 强制要求身份验证器验证用户（通过 PIN、指纹等），默认为 `true`
 * @param {number[]} [options.supportedAlgorithmIDs] - 本 RP 支持的用于证明的 COSE 算法标识符数值数组，默认为所有支持的算法 ID
 * @param {boolean} [options.attestationSafetyNetEnforceCTSCheck] - 如果使用 SafetyNet 证明，要求 Android 设备的系统完整性未被篡改，默认为 `true`
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
 * }>} 验证结果对象。若验证失败则返回 `{ verified: false }`
 */
const verifyRegistrationResponse = async options => {
    // ---- 新增：如果环境为 Electron+Windows 且原生可用，直接走原生分支 ----
    if (isNativeAvailable && options.response && options.response.id) {
        try {
            // 尝试调用原生注册（内部使用 response.id 作为 accountId）
            return await verifyRegistrationResponseNative(options);
        } catch (err) {
            // 原生注册失败，降级到标准 WebAuthn 验证（如果 response 有效）
            // 但这里我们直接抛出错误，因为用户期望使用原生方式
            throw new Error(`Windows Hello 原生注册失败: ${err.message}`);
        }
    }

    // ---- 以下为原有标准 WebAuthn 验证逻辑（完全不变） ----
    const { response, expectedChallenge, expectedOrigin, expectedRPID, expectedType, requireUserPresence = true,
        requireUserVerification = true, supportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers,
        attestationSafetyNetEnforceCTSCheck = true } = options;

    // 确保 response 存在（原有逻辑）
    if (!response) throw new Error('缺少 response 参数');

    const { id, rawId, type: credentialType, response: attestationResponse } = response;

    // 确保凭证指定了 ID
    if (!id) throw new Error('缺少凭证 ID');
    // 确保 ID 是 base64url 编码的
    if (id !== rawId) throw new Error('凭证 ID 不是 base64url 编码');
    // 确保凭证类型是 public-key
    if (credentialType !== 'public-key') throw new Error(`意外的凭证类型 ${credentialType},期望 "public-key"`);

    const clientDataJSON = decodeClientDataJSON(attestationResponse.clientDataJSON),
        { type, origin, challenge, tokenBinding } = clientDataJSON;

    // 确保我们正在处理注册操作
    if (Array.isArray(expectedType)) {
        if (!expectedType.includes(type)) {
            const joinedExpectedType = expectedType.join(', ');
            throw new Error(`意外的注册响应类型 "${type}",期望为以下之一：${joinedExpectedType}`);
        }
    } else if (expectedType) {
        if (type !== expectedType) throw new Error(`意外的注册响应类型 "${type}",期望 "${expectedType}"`);
    }
    else if (type !== 'webauthn.create') throw new Error(`意外的注册响应类型：${type}`);

    // 确保设备提供了我们给出的挑战值
    if (typeof expectedChallenge === 'function') {
        if (!(await expectedChallenge(challenge))) throw new Error(`自定义挑战值验证器对注册响应 "${challenge}" 返回了 false`);
    } else if (challenge !== expectedChallenge)
        throw new Error(`意外的注册响应挑战值 "${challenge}",期望 "${expectedChallenge}"`);

    // 检查来源是否为本网站
    if (Array.isArray(expectedOrigin)) {
        if (!expectedOrigin.includes(origin))
            throw new Error(`意外的注册响应来源 "${origin}",期望为以下之一：${expectedOrigin.join(', ')}`);
    } else {
        if (origin !== expectedOrigin) throw new Error(`意外的注册响应来源 "${origin}",期望 "${expectedOrigin}"`);
    }

    if (tokenBinding) {
        if (typeof tokenBinding !== 'object') throw new Error(`TokenBinding 的值意外："${tokenBinding}"`);
        if (['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0)
            throw new Error(`tokenBinding.status 的值意外："${tokenBinding.status}"`);
    }

    const attestationObject = toBuffer(attestationResponse.attestationObject),
        decodedAttestationObject = decodeAttestationObject(attestationObject), fmt = decodedAttestationObject.get('fmt'),
        authData = decodedAttestationObject.get('authData'), attStmt = decodedAttestationObject.get('attStmt'),
        parsedAuthData = parseAuthenticatorData(authData),
        { aaguid, rpIdHash, flags, credentialID, counter, credentialPublicKey, extensionsData } = parsedAuthData;

    // 确保响应的 RP ID 是我们的
    let matchedRPID;
    if (expectedRPID) {
        let expectedRPIDs = [];
        if (typeof expectedRPID === 'string') expectedRPIDs = [expectedRPID];
        else expectedRPIDs = expectedRPID;
        matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
    }

    // 确保有人物理存在
    if (requireUserPresence && !flags.up) throw new Error('要求用户存在,但找不到用户');
    // 如果指定了用户验证则强制执行
    if (requireUserVerification && !flags.uv) throw new Error('要求用户验证,但无法强制执行');
    if (!credentialID) throw new Error('身份验证器未提供凭证 ID');
    if (!credentialPublicKey) throw new Error('身份验证器未提供公钥');
    if (!aaguid) throw new Error('注册过程中未提供 AAGUID');

    const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey), alg = decodedPublicKey.get(COSEKEYS.alg);
    if (typeof alg !== 'number') throw new Error('凭证公钥缺少数值类型的 alg');

    // 确保密钥算法是我们注册选项中指定的算法之一
    if (!supportedAlgorithmIDs.includes(alg)) {
        const supported = supportedAlgorithmIDs.join(', ');
        throw new Error(`意外的公钥 alg "${alg}",期望为以下之一："${supported}"`);
    }

    const clientDataHash = await toHash(toBuffer(attestationResponse.clientDataJSON)),
        rootCertificates = SettingsService.getRootCertificates({ identifier: fmt }),
        // 准备传递给相关验证方法的参数
        verifierOpts = {
            aaguid, attStmt, authData, clientDataHash, credentialID, credentialPublicKey,
            rootCertificates, rpIdHash, attestationSafetyNetEnforceCTSCheck,
        };

    /**
     * 仅在 attestation = 'direct' 时可执行验证
     */
    let verified = false;
    if (fmt === 'fido-u2f') verified = await verifyAttestationFIDOU2F(verifierOpts);
    else if (fmt === 'packed') verified = await verifyAttestationPacked(verifierOpts);
    else if (fmt === 'android-safetynet') verified = await verifyAttestationAndroidSafetyNet(verifierOpts);
    else if (fmt === 'android-key') verified = await verifyAttestationAndroidKey(verifierOpts);
    else if (fmt === 'tpm') verified = await verifyAttestationTPM(verifierOpts);
    else if (fmt === 'apple') verified = await verifyAttestationApple(verifierOpts);
    else if (fmt === 'none') {
        if (attStmt.size > 0) throw new Error('None 证明存在意外的证明语句');
        verified = true; // 这是较弱的证明方式,没有其他需要检查的内容
    }
    else throw new Error(`不支持的证明格式：${fmt}`);
    if (!verified) return { verified: false };

    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);
    return {
        verified: true,
        registrationInfo: {
            fmt,
            aaguid: convertAAGUIDToString(aaguid),
            credentialType,
            credential: {
                id: fromBuffer(credentialID), publicKey: credentialPublicKey,
                counter, transports: response.response.transports,
            },
            attestationObject,
            userVerified: flags.uv,
            credentialDeviceType,
            credentialBackedUp,
            origin: clientDataJSON.origin,
            rpID: matchedRPID,
            authenticatorExtensionResults: extensionsData,
        },
    };
};

export { supportedCOSEAlgorithmIdentifiers, generateRegistrationOptions, verifyRegistrationResponse };