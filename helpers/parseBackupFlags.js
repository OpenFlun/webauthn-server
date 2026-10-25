/**
 * 当解析备份标志(be/bs)时遇到无效组合抛出的错误(如单设备凭证标记为已备份);
 * - 查看定义:@see {@link InvalidBackupFlags}
 * @extends {Error}
 */
class InvalidBackupFlags extends Error {
    constructor(message) {
        super(message), this.name = 'InvalidBackupFlags';
    }
}

/**
 * 解析身份验证器返回的比特位 3 和 4,用于判断:
 *
 * - 凭证是否可以在多设备上使用
 * - 凭证是否已备份
 * > 无效的配置将抛出 `Error`
 * - 查看定义:@see {@link parseBackupFlags}
 *
 * @param {Object} flags - 包含备份标志位的对象
 * @param {boolean} flags.be - 备份资格标志(Backup Eligibility)
 * @param {boolean} flags.bs - 备份状态标志(Backup State)
 * @returns {{ credentialDeviceType: 'singleDevice' | 'multiDevice', credentialBackedUp: boolean }}
 *   返回凭证设备类型和备份状态:
 *   - `credentialDeviceType`: `'singleDevice'` 表示单设备凭证,`'multiDevice'` 表示多设备凭证
 *   - `credentialBackedUp`: `true` 表示凭证已备份,`false` 表示未备份
 * @throws {InvalidBackupFlags} 当 `be` 为 `false`(单设备)且 `bs` 为 `true`(已备份)时抛出
 */
const parseBackupFlags = ({ be, bs }) => {
    const credentialBackedUp = bs;
    let credentialDeviceType = 'singleDevice';
    if (be) credentialDeviceType = 'multiDevice';
    if (credentialDeviceType === 'singleDevice' && credentialBackedUp)
        throw new InvalidBackupFlags('单设备凭证指示其已被备份,这应该是不可能的;请检查您的身份验证器是否正确实现了规范');
    return { credentialDeviceType, credentialBackedUp };
};

export { parseBackupFlags, InvalidBackupFlags };