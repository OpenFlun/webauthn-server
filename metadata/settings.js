import { convertCertBufferToPEM } from '../helpers/index.js';
import {
    Google_Hardware_Attestation_Root_1, Google_Hardware_Attestation_Root_2, Google_Hardware_Attestation_Root_3,
    Google_Hardware_Attestation_Root_4, GlobalSign_Root_CA, GlobalSign_Root_CA_R3, Apple_WebAuthn_Root_CA
} from './defaultRootCerts/index.js';


/**
 * 基础设置服务类,用于管理各类 attestation 语句格式的根证书
 * - 查看定义:@see {@link BaseSettingsService}
 */
class BaseSettingsService {
    /**
     * @type {Map<string, string[]>}
     */
    pemCertificates = new Map();

    /**
     * 设置指定标识符的根证书列表
     * @param {Object} opts 配置项
     * @param {string} opts.identifier 证书标识符(如 'android-key')
     * @param {(Uint8Array|string)[]} opts.certificates 证书数组,支持 Uint8Array 或 PEM 字符串
     * @returns {void}
     */
    setRootCertificates(opts) {
        const { identifier, certificates } = opts, newCertificates = [];
        for (const cert of certificates) {
            if (cert instanceof Uint8Array) newCertificates.push(convertCertBufferToPEM(cert));
            else newCertificates.push(cert);
        }
        this.pemCertificates.set(identifier, newCertificates);
    }

    /**
     * 获取指定标识符的根证书列表
     * @param {Object} opts 配置项
     * @param {string} opts.identifier 证书标识符
     * @returns {string[]} 证书 PEM 字符串数组,若不存在则返回空数组
     */
    getRootCertificates(opts) {
        const { identifier } = opts;
        return this.pemCertificates.get(identifier) ?? [];
    }
}

/**
 * 一个基础服务,用于指定所有支持 attestation 语句格式接受的根证书;
 *
 * 此外,默认包含以下语句格式的根证书:
 *
 * - `'android-key'`
 * - `'android-safetynet'`
 * - `'apple'`
 * - `'mds'`
 *
 * 可以通过 `setRootCertificates()` 为特定格式标识符设置替代根证书来覆盖默认值;
 * - 查看定义:@see {@link SettingsService}
 *
 * @type {BaseSettingsService}
 */
const SettingsService = new BaseSettingsService();

// 初始化默认证书
SettingsService.setRootCertificates({
    identifier: 'android-key',
    certificates: [
        Google_Hardware_Attestation_Root_1, Google_Hardware_Attestation_Root_2,
        Google_Hardware_Attestation_Root_3, Google_Hardware_Attestation_Root_4
    ],
});

SettingsService.setRootCertificates({
    identifier: 'android-safetynet', certificates: [GlobalSign_Root_CA]
});

SettingsService.setRootCertificates({
    identifier: 'apple', certificates: [Apple_WebAuthn_Root_CA]
});

SettingsService.setRootCertificates({
    identifier: 'mds', certificates: [GlobalSign_Root_CA_R3]
});

export { BaseSettingsService, SettingsService };