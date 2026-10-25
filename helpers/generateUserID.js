import { getRandomValues } from './iso/index.js';

/**
 * 使得在测试过程中可以模拟(stub)该函数的返回值
 * - 查看定义:@see {@link _generateUserIDInternals}
 * @ignore 不要将此内容包含在文档输出中
 * @type {{ stubThis: (value: Uint8Array) => Uint8Array }}
 */
const _generateUserIDInternals = { stubThis: value => value };

/**
 * 生成一个适合作为用户 ID 的随机值
 * - 查看定义:@see {@link generateUserID}
 * @returns {Promise<Uint8Array>} 返回一个包含 32 字节随机数的 Uint8Array
 */
const generateUserID = async () => {
    /**
     * WebAuthn 规范规定 user.id 的最大长度为 64 字节;
     * 我个人更倾向于 32 字节随机值经过 base64url 编码后的效果,因此这里选择使用 32 字节;
     */
    const newUserID = new Uint8Array(32);
    await getRandomValues(newUserID);
    return _generateUserIDInternals.stubThis(newUserID);
};

export { _generateUserIDInternals, generateUserID };