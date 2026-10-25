import { getRandomValues } from './iso/index.js';

/**
 * 使得在测试期间可以存根(stub)返回值
 * - 查看定义:@see {@link _generateChallengeInternals}
 * @ignore 不要在文档输出中包含此项
 * @type {{ stubThis: <T>(value: T) => T }}
 */
const _generateChallengeInternals = { stubThis: value => value };

/**
 * 生成一个合适的随机值,用作证明或断言的挑战值
 * - 查看定义:@see {@link generateChallenge}
 * @returns {Promise<Uint8Array>} 返回一个包含 32 字节随机值的 Promise
 */
const generateChallenge = async () => {
    /**
     * WebAuthn 规范建议至少使用 16 字节:
     *
     * "为了防止重放攻击,挑战值必须包含足够的熵,使得猜测它们不可行;
     * 因此,挑战值应该至少为 16 字节长;"
     *
     * 为了保险起见,我们将其长度翻倍
     */
    const challenge = new Uint8Array(32);
    await getRandomValues(challenge);
    return _generateChallengeInternals.stubThis(challenge);
};

export { _generateChallengeInternals, generateChallenge };