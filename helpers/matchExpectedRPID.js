import { toHash } from './toHash.js';
import { asciiToBytes, areEqual } from './iso/index.js';

/**
 * 当响应中的 RP ID 哈希值与所有预期的 RP ID 均不匹配时抛出的错误;
 * - 查看定义:@see {@link UnexpectedRPIDHash}
 * @extends {Error}
 */
class UnexpectedRPIDHash extends Error {
    /**
     * 构造一个 UnexpectedRPIDHash 错误实例
     */
    constructor() {
        const message = '意外的 RP ID 哈希值';
        super(message), this.name = 'UnexpectedRPIDHash';
    }
}

/**
 * 遍历所有预期的 RP ID,找出与响应中哈希值匹配的项,并返回对应的原始 RP ID
 * 如果未找到匹配项,则抛出 `UnexpectedRPIDHash` 错误;
 * - 查看定义:@see {@link matchExpectedRPID}
 *
 * @param {ArrayBuffer} rpIDHash - 响应中获取的 RP ID 哈希值(原始二进制数据)
 * @param {string[]} expectedRPIDs - 预期的有效 RP ID 字符串列表
 * @returns {Promise<string>} 解析为匹配成功的 RP ID 字符串
 * @throws {UnexpectedRPIDHash} 当所有预期 RP ID 的哈希均不匹配时抛出错误
 */
const matchExpectedRPID = async (rpIDHash, expectedRPIDs) => {
    try {
        const matchedRPID = await Promise.any(expectedRPIDs.map(expected => {
            return new Promise((resolve, reject) => {
                toHash(asciiToBytes(expected)).then(expectedRPIDHash => {
                    if (areEqual(rpIDHash, expectedRPIDHash)) resolve(expected);
                    else reject();
                });
            });
        }));
        return matchedRPID;
    }
    catch (err) {
        // 表示没有找到任何匹配项
        if (err.name === 'AggregateError') throw new UnexpectedRPIDHash();
        throw err; // 发生了意外错误,重新抛出
    }
}

export { matchExpectedRPID, UnexpectedRPIDHash };