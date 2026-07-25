import {
    isBase64URL, toBuffer, fromBuffer, trimPadding, concat, utf8Tobytes, generateChallenge, toHash, getPassportClass,
    parseAndValidateClientData, validateResponseStructure, parseAuthenticatorData, parseBackupFlags, matchExpectedRPID,
    verifySignature
} from '../helpers/index.js';
import { createPublicKey, createVerify } from 'node:crypto';

/**
 * 生成用于 WebAuthn 认证的参数,可直接传递给 `navigator.credentials.get()`
 * - 查看定义: @see {@link generateAuthenticationOptions}
 * @param {Object} options - 配置选项
 * @param {string} options.rpID - 有效的域名（`https://` 之后的部分）
 * @param {BufferSource} [options.challenge] - 随机挑战值,若不提供则自动生成
 * @param {PublicKeyCredentialDescriptor[]} [options.allowCredentials] - 之前注册过的凭证列表,用于限制可用的凭证
 * @param {number} [options.timeout] - 超时毫秒数,默认 60000
 * @param {UserVerificationRequirement} [options.userVerification] - 用户验证要求,默认 'preferred'
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
        allowCredentials, challenge = await generateChallenge(), timeout = 60000, userVerification = 'preferred',
        extensions, rpID
    } = options;
    let _challenge = challenge;
    if (typeof _challenge === 'string') _challenge = utf8Tobytes(_challenge);
    return {
        rpId: rpID,
        challenge: fromBuffer(_challenge),
        allowCredentials: allowCredentials?.map(cred => {
            if (!isBase64URL(cred.id)) throw new Error(`allowCredential id "${cred.id}"不是合法的base64url字符串`);
            return { ...cred, id: trimPadding(cred.id), type: 'public-key' };
        }),
        timeout, userVerification, extensions
    };
};

/**
 * 使用 Windows Hello（Passport）进行原生认证签名验证；
 * 仅在 Windows 环境且 `response.native === true` 时被调用；
 * @ignore
 * @param {Object} options - 内部参数
 * @param {Object} options.credential - 存储的凭证信息（包含 id 和 publicKey）
 * @param {string|Buffer} options.expectedChallenge - 预期的挑战值
 * @param {string} options.expectedOrigin - 预期的来源
 * @param {string} options.expectedRPID - 预期的 RP ID
 * @param {Function} options.PassportClass - 由 `getPassportClass` 返回的 Passport 类构造函数
 * @returns {Promise<{ verified: true, authenticationInfo: Object }>}
 * @throws {Error} 如果账户不存在或签名验证失败
 */
const verifyAuthenticationResponseNative = async options => {
    const { credential, expectedChallenge, expectedOrigin, expectedRPID, PassportClass } = options,
        accountId = credential.id;

    if (!accountId) throw new Error('缺少凭证 ID,无法用于 Windows Hello 认证');
    const passport = new PassportClass(accountId);
    if (!passport.accountExists) throw new Error(`账号 ${accountId} 不存在,请先注册`);
    const challengeBuffer = toBuffer(expectedChallenge), signature = await passport.sign(challengeBuffer),
        publicKeyDer = credential.publicKey, verify = createVerify('SHA256'),
        key = createPublicKey({ key: publicKeyDer, format: 'der', type: 'pkcs1' });

    verify.write(challengeBuffer), verify.end();
    const verified = verify.verify(key, signature);
    if (!verified) throw new Error('签名验证失败');
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
            origin: expectedOrigin
        }
    };
};

/**
 * 验证用户是否合法完成了 WebAuthn 认证流程；
 * - 查看定义: @see {@link verifyAuthenticationResponse}
 * @param {Object} options - 验证选项
 * @param {Object} options.response - 由 `@flun/webauthn-browser` 的 `startAuthentication()` 返回的响应对象
 * @param {string} options.response.id - 凭证 ID（base64url 字符串）
 * @param {string} options.response.rawId - 原始凭证 ID（应与 `id` 相同）
 * @param {'public-key'} options.response.type - 凭证类型,必须为 `"public-key"`
 * @param {Object} options.response.response - 认证断言响应数据
 * @param {string} options.response.response.clientDataJSON - 客户端数据 JSON（字符串）
 * @param {string} options.response.response.authenticatorData - 认证器数据（base64url 字符串）
 * @param {string} options.response.response.signature - 签名（base64url 字符串）
 * @param {string} [options.response.response.userHandle] - 用户句柄（可选）
 * @param {boolean} [options.response.native] - 显式标记是否使用 Windows Hello 原生验证,默认为 false
 * @param {string|Function} options.expectedChallenge - Base64URL 编码的 challenge,
 * 即 `generateAuthenticationOptions()`返回的值,也可传入自定义验证函数`(challenge: string) => boolean | Promise<boolean>`
 * @param {string|string[]} options.expectedOrigin - 期望的网站 URL（或 URL 数组）
 * @param {string|string[]} options.expectedRPID - 期望的 RP ID（或 ID 数组）
 * @param {Object} options.credential - 与认证响应中的 `id` 对应的内部存储凭证
 * @param {string} options.credential.id - 凭证 ID
 * @param {BufferSource} options.credential.publicKey - 凭证公钥（CryptoKey 或 BufferSource）
 * @param {number} options.credential.counter - 上一次记录的签名计数器值
 * @param {string|string[]} [options.expectedType='webauthn.get'] - 期望的响应类型
 * @param {boolean} [options.requireUserVerification=true] - 强制要求身份验证器进行用户验证（通过 PIN、指纹等）
 * @param {Object} [options.advancedFIDOConfig] - 用于满足更严格的 FIDO 依赖方（RP）功能要求的选项
 * @param {'required'|'preferred'|'discouraged'} [options.advancedFIDOConfig.userVerification] -启用替代规则评估 UP/UV 标志
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
    const {
        response, expectedChallenge, expectedOrigin, expectedRPID, expectedType, credential,
        requireUserVerification = true, advancedFIDOConfig
    } = options, passportClass = getPassportClass('[auth]');

    if (!response?.id) throw new Error('缺少凭证 ID');
    if (passportClass && response.native === true) {
        try {
            return await verifyAuthenticationResponseNative({
                credential, expectedChallenge, expectedOrigin, expectedRPID, PassportClass: passportClass
            });
        } catch (err) {
            throw new Error(`Windows Hello 原生认证失败: ${err.message}`);
        }
    }
    validateResponseStructure(response);
    const { response: assertionResponse } = response,
        clientData = await parseAndValidateClientData(
            assertionResponse.clientDataJSON, expectedType || 'webauthn.get', expectedChallenge, expectedOrigin
        );

    if (!isBase64URL(assertionResponse.authenticatorData))
        throw new Error('凭证响应中的 authenticatorData 不是 base64url 字符串');
    if (!isBase64URL(assertionResponse.signature))
        throw new Error('凭证响应中的 signature 不是 base64url 字符串');
    if (assertionResponse.userHandle && typeof assertionResponse.userHandle !== 'string')
        throw new Error('凭证响应中的 userHandle 不是字符串');

    const authDataBuffer = toBuffer(assertionResponse.authenticatorData),
        parsedAuthData = parseAuthenticatorData(authDataBuffer), { rpIdHash, flags, counter, extensionsData } = parsedAuthData;
    let expectedRPIDs = [];
    if (typeof expectedRPID === 'string') expectedRPIDs = [expectedRPID];
    else expectedRPIDs = expectedRPID;
    const matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
    if (advancedFIDOConfig !== undefined) {
        const { userVerification: fidoUserVerification } = advancedFIDOConfig;
        if (fidoUserVerification === 'required' && !flags.uv) throw new Error('需要用户验证,但用户无法被验证');
    } else {
        if (!flags.up) throw new Error('认证过程中用户未出现');
        if (requireUserVerification && !flags.uv) throw new Error('需要用户验证,但用户无法被验证');
    }
    const clientDataHash = await toHash(toBuffer(assertionResponse.clientDataJSON)),
        signatureBase = concat([authDataBuffer, clientDataHash]), signature = toBuffer(assertionResponse.signature);

    if ((counter > 0 || credential.counter > 0) && counter <= credential.counter)
        throw new Error(`响应中的 counter 值 ${counter} 低于期望值 ${credential.counter}`);
    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);
    return {
        verified: await verifySignature({ signature, data: signatureBase, credentialPublicKey: credential.publicKey }),
        authenticationInfo: {
            rpID: matchedRPID,
            newCounter: counter,
            credentialID: credential.id,
            userVerified: flags.uv,
            credentialDeviceType,
            credentialBackedUp,
            authenticatorExtensionResults: extensionsData,
            origin: clientData.origin
        }
    };
};

export { generateAuthenticationOptions, verifyAuthenticationResponse };