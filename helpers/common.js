import { createRequire } from 'module';
import { decodeClientDataJSON } from './decodeClientDataJSON.js';

let PassportClass = null, nativeLoaded = false;
const require = createRequire(import.meta.url);
/**
 * 加载 Windows Hello 原生模块（仅 Windows）
 * - 查看定义:@see {@link getPassportClass}
 * @param {string} logPrefix - 日志前缀,默认 '[common]'
 * @returns {object|null} Passport 类或 null
 */
const getPassportClass = (logPrefix = '[common]') => {
    if (nativeLoaded) return PassportClass;
    if (process.platform !== 'win32') return null;
    const arch = process.arch, pkgName = `passport-desktop-win32-${arch}-msvc`;
    try {
        const binding = require(pkgName);
        if (binding.Passport) PassportClass = binding.Passport;
        else if (typeof binding.available === 'function') PassportClass = binding;
        if (PassportClass?.available?.()) return nativeLoaded = true, PassportClass;
        return null;
    } catch (err) {
        return console.error(`${logPrefix} ❌ 加载原生模块失败:`, err.message), null;
    }
};

/**
 * 校验标准 WebAuthn 凭证的 rawId 和 type（仅标准路径使用）
 * - 查看定义:@see {@link validateResponseStructure}
 * @param {object} response - 凭证响应对象
 * @throws {Error} 校验失败时抛出
 */
const validateResponseStructure = (response) => {
    if (response.id !== response.rawId) throw new Error('凭证 ID 不是 base64url 编码');
    if (response.type !== 'public-key') throw new Error(`意外的凭证类型 ${response.type}, 期望 "public-key"`);
};

/**
 * 解析并验证 clientDataJSON（type, challenge, origin, tokenBinding）
 * - 查看定义:@see {@link parseAndValidateClientData}
 * @param {string} clientDataJSON - base64url 编码的 clientDataJSON 字符串
 * @param {string|string[]} expectedType - 期望的 type 值或数组
 * @param {string|Function} expectedChallenge - 期望的 challenge 字符串或异步验证函数
 * @param {string|string[]} expectedOrigin - 期望的 origin 值或数组
 * @returns {Promise<object>} 解析后的 clientData 对象（包含 type, origin, challenge, tokenBinding 等）
 * @throws {Error} 任何校验失败时抛出
 */
const parseAndValidateClientData = async (clientDataJSON, expectedType, expectedChallenge, expectedOrigin) => {
    if (typeof clientDataJSON !== 'string') throw new Error('clientDataJSON 不是字符串');
    const clientData = decodeClientDataJSON(clientDataJSON), { type, origin, challenge, tokenBinding } = clientData;

    if (expectedType != null) {
        const types = Array.isArray(expectedType) ? expectedType : [expectedType];
        if (!types.includes(type)) throw new Error(`意外的响应类型 "${type}", 期望以下之一：${types.join(', ')}`);
    }
    if (expectedOrigin != null) {
        const origins = Array.isArray(expectedOrigin) ? expectedOrigin : [expectedOrigin];
        if (!origins.includes(origin)) throw new Error(`意外的响应来源 "${origin}", 期望以下之一：${origins.join(', ')}`);
    }
    if (expectedChallenge != null) {
        if (typeof expectedChallenge === 'function') {
            const result = await expectedChallenge(challenge);
            if (!result) throw new Error(`自定义 challenge 验证器对响应中的 challenge "${challenge}" 返回了 false`);
        }
        else if (challenge !== expectedChallenge)
            throw new Error(`意外的响应 challenge "${challenge}", 期望 "${expectedChallenge}"`);
    }
    if (tokenBinding) {
        if (typeof tokenBinding !== 'object')
            throw new Error(`ClientDataJSON 中的 tokenBinding 不是对象，值为：${tokenBinding}`);
        if (!['present', 'supported', 'notSupported'].includes(tokenBinding.status))
            throw new Error(`意外的 tokenBinding 状态：${tokenBinding.status}`);
    }

    return clientData;
};

export { getPassportClass, validateResponseStructure, parseAndValidateClientData };