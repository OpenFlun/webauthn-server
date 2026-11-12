import {
    Apple_WebAuthn_Root_CA, GlobalSign_Root_CA, GlobalSign_Root_CA_R3, Google_Hardware_Attestation_Root_1,
    Google_Hardware_Attestation_Root_2, Google_Hardware_Attestation_Root_3, Google_Hardware_Attestation_Root_4
} from './defaultRootCerts/certs.js';
import {
    AlgSign, MetadataService, algSignToCOSEInfoMap, parseJWT, verifyAttestationWithMetadata, verifyJWT,
    verifyMDSBlob, BaseMetadataService
} from './metadata.js';
import { SettingsService, BaseSettingsService } from './settings.js';


// ================================= defaultRootCerts模块导出 =================================

/**
 * ```js
 * // 文件导出内容(硬件认证根证书)
 * const Apple_WebAuthn_Root_CA='', GlobalSign_Root_CA='', GlobalSign_Root_CA_R3='';
 * const Google_Hardware_Attestation_Root_1='', Google_Hardware_Attestation_Root_2='';
 * const Google_Hardware_Attestation_Root_3='', Google_Hardware_Attestation_Root_4='';
 * ```
 * >查看定义:@see {@link Apple_WebAuthn_Root_CA}、{@link GlobalSign_Root_CA}、{@link GlobalSign_Root_CA_R3}、
 * {@link Google_Hardware_Attestation_Root_1}、{@link Google_Hardware_Attestation_Root_2}、
 * {@link Google_Hardware_Attestation_Root_3}、{@link Google_Hardware_Attestation_Root_4}
 */
declare module './defaultRootCerts/index.js' {
    export * from './defaultRootCerts/certs.js';
}

// ================================= metadata.js =================================
/**
 *
 * 文件导出内容:
 * ```js
 * const AlgSign=[];                               // 支持的签名算法数组
 * const algSignToCOSEInfoMap={};                  // 将 ALG_SIGN 值转换为 COSE 信息
 * const MetadataService= new BaseMetadataService; // 用于协调与 FIDO 元数据交互的基础服务;
 * parseJWT();                                     // 将 JWT 处理为 JavaScript 友好的数据结构
 * verifyAttestationWithMetadata();                // 将身份验证器的证明声明属性与 FIDO 联盟元数据服务中注册的预期值进行
 * verifyJWT();                                    // 对对 FIDO MDS JWT 的轻量级验证(支持EC2和RSA算法);
 * verifyMDSBlob();      // 对 BLOB 进行真实性与完整性验证,并提取其中包含的 FIDO2,该方法会发起网络请求以执行CRL检查等操作;
 * class BaseMetadataService{};                    // 下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * ```
 * >查看定义:@see {@link AlgSign}、{@link algSignToCOSEInfoMap}、{@link MetadataService}、{@link parseJWT}、
 * {@link verifyAttestationWithMetadata}、{@link verifyJWT}、{@link verifyMDSBlob}、{@link BaseMetadataService}
 */
declare module './metadata.js' {
    export * from './metadata.js';
}

// ================================= settings.js =================================
/**
 * ```js
 * // 文件导出内容
 * const SettingsService= new BaseSettingsService; // 用于为所有支持的证明声明格式指定可接受的根证书;
 * class BaseSettingsService{};                    // 用于管理各类 attestation 语句格式的根证书;
 * ```
 * >查看定义:@see {@link SettingsService}、{@link BaseSettingsService}
 */
declare module './settings.js' {
    export * from './settings.js';
}

// ================================= 整体导出入口 =================================
/**
 *
 * 模块导出内容:
 * ```js
 * const AlgSign=[];                               // 支持的签名算法数组
 * const algSignToCOSEInfoMap={};                  // 将 ALG_SIGN 值转换为 COSE 信息
 * const MetadataService= new BaseMetadataService; // 用于协调与 FIDO 元数据交互的基础服务;
 * const SettingsService= new BaseSettingsService; // 用于为所有支持的证明声明格式指定可接受的根证书;
 * parseJWT();                                     // 将 JWT 处理为 JavaScript 友好的数据结构
 * verifyAttestationWithMetadata();                // 将身份验证器的证明声明属性与 FIDO 联盟元数据服务中注册的预期值进行
 * verifyJWT();                                    // 对对 FIDO MDS JWT 的轻量级验证(支持EC2和RSA算法);
 * verifyMDSBlob();      // 对 BLOB 进行真实性与完整性验证,并提取其中包含的 FIDO2,该方法会发起网络请求以执行CRL检查等操作;
 * class BaseMetadataService{};                    // 下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * class BaseSettingsService{};                    // 用于管理各类 attestation 语句格式的根证书;
 * ```
 * >查看定义:@see {@link AlgSign}、{@link algSignToCOSEInfoMap}、{@link MetadataService}、{@link SettingsService}、
 * {@link parseJWT}、{@link verifyAttestationWithMetadata}、{@link verifyJWT}、{@link verifyMDSBlob}、
 * {@link BaseMetadataService}、{@link BaseSettingsService}
 */
declare module './index.js' {
    export * from './metadata.js';
    export * from './settings.js';
}