import {
    isBase64URL, toBuffer, fromBuffer, trimPadding, concat, utf8Tobytes, generateChallenge,
    decodeClientDataJSON, toHash, verifySignature, parseAuthenticatorData, parseBackupFlags, matchExpectedRPID
} from '../helpers/index.js';

// ========== 新增：直接加载独立的 .node 包（Electron + Windows） ==========
import { createRequire } from 'module';
import { createPublicKey, createVerify } from 'node:crypto';
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

// ================================= 生成验证器认证参数 =================================
/**
 * 生成用于身份验证器认证的参数
 * - 查看定义:@see {@link generateAuthenticationOptions}
 * @param {Object} options - 配置选项
 * @param {string} options.rpID - 有效的域名（`https://` 之后的部分）
 * @param {BufferSource} [options.challenge] - 随机挑战值
 * @param {PublicKeyCredentialDescriptor[]} [options.allowCredentials] - 之前注册过的凭证列表
 * @param {number} [options.timeout] - 超时毫秒数，默认 60000
 * @param {UserVerificationRequirement} [options.userVerification] - 用户验证要求
 * @param {AuthenticationExtensionsClientInputs} [options.extensions] - 扩展项
 * @returns {Promise<{
 *   rpId: string,
 *   challenge: string,
 *   allowCredentials: PublicKeyCredentialDescriptor[],
 *   timeout: number,
 *   userVerification: UserVerificationRequirement,
 *   extensions: AuthenticationExtensionsClientInputs
 * }>}
 */
const generateAuthenticationOptions = async options => {
    const {
        allowCredentials, challenge = await generateChallenge(), timeout = 60000,
        userVerification = 'preferred', extensions, rpID,
    } = options;

    /**
     * 保留对 `string` 类型 challenge 值的支持
     */
    let _challenge = challenge;
    if (typeof _challenge === 'string') _challenge = utf8Tobytes(_challenge);

    return {
        rpId: rpID,
        challenge: fromBuffer(_challenge),
        allowCredentials: allowCredentials?.map(cred => {
            if (!isBase64URL(cred.id)) throw new Error(`allowCredential id "${cred.id}"不是合法的base64url字符串`);

            return { ...cred, id: trimPadding(cred.id), type: 'public-key', };
        }),
        timeout, userVerification, extensions
    };
};

// ================================= 验证是否完成了认证流程 =================================

// ---- 新增：内部原生认证函数 ----
async function verifyAuthenticationResponseNative(options) {
    const {
        credential,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
    } = options;

    const accountId = credential.id;
    if (!accountId) throw new Error('缺少凭证 ID，无法用于 Windows Hello 认证');

    const passport = new PassportClass(accountId);
    if (!passport.accountExists) {
        throw new Error(`账号 ${accountId} 不存在，请先注册`);
    }

    const challengeBuffer = toBuffer(expectedChallenge);
    const signature = await passport.sign(challengeBuffer);

    // 使用 Node crypto 验证签名
    const publicKeyDer = credential.publicKey;
    const key = createPublicKey({
        key: publicKeyDer,
        format: 'der',
        type: 'pkcs1',
    });
    const verify = createVerify('SHA256');
    verify.write(challengeBuffer);
    verify.end();
    const verified = verify.verify(key, signature);

    if (!verified) {
        throw new Error('签名验证失败');
    }

    return {
        verified: true,
        authenticationInfo: {
            rpID: expectedRPID,
            newCounter: 0,
            credentialID: credential.id,
            userVerified: true,
            credentialDeviceType: 'multiDevice',
            credentialBackedUp: false,
            authenticatorExtensionResults: {},
            origin: expectedOrigin,
        },
    };
}

/**
 * 验证用户是否合法完成了认证流程
 * - 查看定义:@see {@link verifyAuthenticationResponse}
 * @param {Object} options - 配置选项
 * @param {Object} options.response - 由 **@flun/webauthn-browser** 的 `startAuthentication()` 返回的响应
 * @param {string} options.response.id - 凭证 ID（base64url 字符串）
 * @param {string} options.response.rawId - 原始凭证 ID（应与 `id` 相同）
 * @param {'public-key'} options.response.type - 凭证类型，必须为 `"public-key"`
 * @param {Object} options.response.response - 认证断言响应数据
 * @param {string} options.response.response.clientDataJSON - 客户端数据 JSON（字符串）
 * @param {string} options.response.response.authenticatorData - 认证器数据（base64url 字符串）
 * @param {string} options.response.response.signature - 签名（base64url 字符串）
 * @param {string} [options.response.response.userHandle] - 用户句柄（可选）
 *
 * @param {string|Function} options.expectedChallenge - Base64URL 编码的 `options.challenge`,即 `generateAuthenticationOptions()`返回的值；
 *                                                       也可传入自定义验证函数 `(challenge: string) => boolean | Promise<boolean>`
 * @param {string|string[]} options.expectedOrigin - 认证应发生的网站 URL（或 URL 数组）
 * @param {string|string[]} options.expectedRPID - 认证选项中指定的 RP ID（或 ID 数组）
 * @param {Object} options.credential - 与认证响应中的 `id` 对应的内部存储凭证
 * @param {string} options.credential.id - 凭证 ID
 * @param {BufferSource} options.credential.publicKey - 凭证公钥（CryptoKey 或 BufferSource）
 * @param {number} options.credential.counter - 上一次记录的签名计数器值
 *
 * @param {string|string[]} [options.expectedType='webauthn.get'] - 期望的响应类型（例如 `'webauthn.get'`）
 * @param {boolean} [options.requireUserVerification=true] - 强制要求身份验证器进行用户验证（通过 PIN、指纹等）
 * @param {Object} [options.advancedFIDOConfig] - 用于满足更严格的 FIDO 依赖方（RP）功能要求的选项
 * @param {'required'|'preferred'|'discouraged'} [options.advancedFIDOConfig.userVerification] - 启用替代规则来评估认证器数据中的
 *                                                                                              用户存在（UP）和用户验证（UV）标志
 *
 * @returns {Promise<{
 *   verified: boolean,
 *   authenticationInfo: {
 *     rpID: string,
 *     newCounter: number,
 *     credentialID: string,
 *     userVerified: boolean,
 *     credentialDeviceType: 'singleDevice' | 'multiDevice',
 *     credentialBackedUp: boolean,
 *     authenticatorExtensionResults: AuthenticationExtensionsAuthenticatorOutputs,
 *     origin: string
 *   }
 * }>} 验证结果,包含签名是否有效以及认证信息
 */
const verifyAuthenticationResponse = async options => {
    // ---- 新增：如果环境为 Electron+Windows 且原生可用，直接走原生分支 ----
    // 注意：认证时使用 credential.id 作为 accountId，无需用户额外传递
    if (isNativeAvailable && options.credential && options.credential.id) {
        try {
            return await verifyAuthenticationResponseNative(options);
        } catch (err) {
            // 原生认证失败，抛出明确错误（不降级，因为用户期望原生方式）
            throw new Error(`Windows Hello 原生认证失败: ${err.message}`);
        }
    }

    // ---- 以下为原有标准 WebAuthn 验证逻辑（完全不变） ----
    const { response, expectedChallenge, expectedOrigin, expectedRPID, expectedType,
        credential, requireUserVerification = true, advancedFIDOConfig } = options;

    // 确保 response 存在（原有逻辑）
    if (!response) throw new Error('缺少 response 参数');

    const { id, rawId, type: credentialType, response: assertionResponse } = response;

    if (!id) throw new Error('缺少凭证 ID');
    if (id !== rawId) throw new Error('凭证 ID 不是 base64url 编码');
    if (credentialType !== 'public-key') throw new Error(`意外的凭证类型 ${credentialType},期望 "public-key"`);
    if (!response) throw new Error('凭证缺少响应');
    if (typeof assertionResponse?.clientDataJSON !== 'string') throw new Error('凭证响应中的 clientDataJSON 不是字符串');

    const clientDataJSON = decodeClientDataJSON(assertionResponse.clientDataJSON),
        { type, origin, challenge, tokenBinding } = clientDataJSON;

    // 确保我们正在处理一次认证
    if (Array.isArray(expectedType)) {
        if (!expectedType.includes(type)) {
            const joinedExpectedType = expectedType.join(', ');
            throw new Error(`意外的认证响应类型 "${type}",期望以下之一：${joinedExpectedType}`);
        }
    } else if (expectedType) {
        if (type !== expectedType) throw new Error(`意外的认证响应类型 "${type}",期望 "${expectedType}"`);
    }
    else if (type !== 'webauthn.get') throw new Error(`意外的认证响应类型：${type}`);

    // 确保设备提供了我们给出的 challenge
    if (typeof expectedChallenge === 'function') {
        if (!(await expectedChallenge(challenge)))
            throw new Error(`自定义 challenge 验证器对注册响应中的 challenge "${challenge}" 返回了 false`);
    }
    else if (challenge !== expectedChallenge)
        throw new Error(`意外的认证响应 challenge "${challenge}"，期望 "${expectedChallenge}"`);

    // 检查 origin 是否为我们的站点
    if (Array.isArray(expectedOrigin)) {
        if (!expectedOrigin.includes(origin)) {
            const joinedExpectedOrigin = expectedOrigin.join(', ');
            throw new Error(`意外的认证响应来源 "${origin}",期望以下之一：${joinedExpectedOrigin}`);
        }
    }
    else if (origin !== expectedOrigin) throw new Error(`意外的认证响应来源 "${origin}",期望 "${expectedOrigin}"`);

    if (!isBase64URL(assertionResponse.authenticatorData))
        throw new Error('凭证响应中的 authenticatorData 不是 base64url 字符串');
    if (!isBase64URL(assertionResponse.signature))
        throw new Error('凭证响应中的 signature 不是 base64url 字符串');
    if (assertionResponse.userHandle && typeof assertionResponse.userHandle !== 'string')
        throw new Error('凭证响应中的 userHandle 不是字符串');
    if (tokenBinding) {
        if (typeof tokenBinding !== 'object') throw new Error('ClientDataJSON 中的 tokenBinding 不是对象');
        if (['present', 'supported', 'notSupported'].indexOf(tokenBinding.status) < 0)
            throw new Error(`意外的 tokenBinding 状态 ${tokenBinding.status}`);
    }

    const authDataBuffer = toBuffer(assertionResponse.authenticatorData),
        parsedAuthData = parseAuthenticatorData(authDataBuffer), { rpIdHash, flags, counter, extensionsData } = parsedAuthData;

    // 确保响应中的 RP ID 是我们的
    let expectedRPIDs = [];
    if (typeof expectedRPID === 'string') expectedRPIDs = [expectedRPID];
    else expectedRPIDs = expectedRPID;

    const matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
    if (advancedFIDOConfig !== undefined) {
        const { userVerification: fidoUserVerification } = advancedFIDOConfig;

        /**
         * 使用 FIDO 一致性测试定义的规则来验证 UP 和 UV 标志
         */
        if (fidoUserVerification === 'required') {
            // 要求 `flags.uv` 为 true（这意味着 `flags.up` 也为 true）
            if (!flags.uv) throw new Error('需要用户验证,但用户无法被验证');
        } else if (fidoUserVerification === 'preferred' || fidoUserVerification === 'discouraged'); // 忽略 `flags.uv`
    } else {
        /**
         * 使用 WebAuthn 规范定义的规则来验证 UP 和 UV 标志
         */
        // WebAuthn 只要求用户存在标志为 true
        if (!flags.up) throw new Error('认证过程中用户未出现');

        // 如果要求用户验证,则强制执行
        if (requireUserVerification && !flags.uv) throw new Error('需要用户验证,但用户无法被验证');
    }

    const clientDataHash = await toHash(toBuffer(assertionResponse.clientDataJSON)),
        signatureBase = concat([authDataBuffer, clientDataHash]),
        signature = toBuffer(assertionResponse.signature);

    // 如果数据库中的 counter 大于或等于 dataStruct 中的 counter,则报错;
    // 这与身份验证器维护其被此客户端使用的次数有关;如果发生这种情况,
    // 说明有人未经由此网站就增加了设备上的计数器;
    if ((counter > 0 || credential.counter > 0) && counter <= credential.counter)
        throw new Error(`响应中的 counter 值 ${counter} 低于期望值 ${credential.counter}`);

    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags),
        toReturn = {
            verified: await verifySignature({
                signature, data: signatureBase, credentialPublicKey: credential.publicKey,
            }),
            authenticationInfo: {
                rpID: matchedRPID, newCounter: counter, credentialID: credential.id, userVerified: flags.uv, credentialDeviceType,
                credentialBackedUp, authenticatorExtensionResults: extensionsData, origin: clientDataJSON.origin
            },
        };

    return toReturn;
};

export { generateAuthenticationOptions, verifyAuthenticationResponse };