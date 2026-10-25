import {
    TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP
} from './verifications/tpm/constants.js';
import { parseCertInfo, parsePubArea } from './verifications/tpm/parse.js';
import { verifyAttestationAndroidKey } from './verifications/verifyAttestationAndroidKey.js';
import { verifyAttestationAndroidSafetyNet } from './verifications/verifyAttestationAndroidSafetyNet.js';
import { verifyAttestationApple } from './verifications/verifyAttestationApple.js';
import { verifyAttestationFIDOU2F } from './verifications/verifyAttestationFIDOU2F.js';
import { verifyAttestationPacked } from './verifications/verifyAttestationPacked.js';
import { verifyAttestationTPM } from './verifications/verifyAttestationTPM.js';
import {
    supportedCOSEAlgorithmIdentifiers, generateRegistrationOptions, verifyRegistrationResponse
} from './registration.js';

// ================================= constants.js =================================
/**
 * ```js
 * // 文件导出内容(TPM结构标签,算法标识符,椭圆曲线,制造商 ID 到厂商名称的映射表,公钥区域曲线 ID 映射)
 * const TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP;
 * ```
 * >查看定义:@see {@link TPM_ST}、{@link TPM_ALG}、{@link TPM_ECC_CURVE }、{@link TPM_MANUFACTURERS}、
 * {@link TPM_ECC_CURVE_COSE_CRV_MAP}
 */
declare module './verifications/tpm/constants.js' {
    export * from './verifications/tpm/constants.js';
}

// ================================= parse.js =================================
/**
 * ```js
 * // 文件导出内容
 * parseCertInfo(); // 将 TPM 证明的 certInfo 解析为可读的片段
 * parsePubArea();  // 解析 TPM 认证信息中的 pubArea 缓冲区
 * ```
 * >查看定义:@see {@link parseCertInfo}、{@link parsePubArea}
 */
declare module './verifications/tpm/parse.js' {
    export * from './verifications/tpm/parse.js';
}

// ================================= verifications/tpm子模块导出 =================================
/**
 * ```js
 * // 模块导出内容:
 *
 * // 常量(TPM结构标签,算法标识符,椭圆曲线,制造商 ID 到厂商名称的映射表,公钥区域曲线 ID 映射)
 * const TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP;
 *
 * // 函数
 * parseCertInfo(); // 将 TPM 证明的 certInfo 解析为可读的片段
 * parsePubArea();  // 解析 TPM 认证信息中的 pubArea 缓冲区
 * ```
 * >查看定义:@see {@link TPM_ST}、{@link TPM_ALG}、{@link TPM_ECC_CURVE }、{@link TPM_MANUFACTURERS}、
 * {@link TPM_ECC_CURVE_COSE_CRV_MAP}、{@link parseCertInfo}、{@link parsePubArea}
 */
declare module './verifications/tpm/index.js' {
    export * from './verifications/tpm/constants.js';
    export * from './verifications/tpm/parse.js';
}

// ================================= verifyAttestationAndroidKey.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationAndroidKey(); // 验证格式为 'android-key' 的 attestation 响应
 * ```
 * >查看定义:@see {@link verifyAttestationAndroidKey}
 */
declare module './verifications/verifyAttestationAndroidKey.js' {
    export * from './verifications/verifyAttestationAndroidKey.js';
}

// ================================= verifyAttestationAndroidSafetyNet.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationAndroidSafetyNet(); // 验证格式为 'android-safetynet' 的证明响应
 * ```
 * >查看定义:@see {@link verifyAttestationAndroidSafetyNet}
 */
declare module './verifications/verifyAttestationAndroidSafetyNet.js' {
    export * from './verifications/verifyAttestationAndroidSafetyNet.js';
}

// ================================= verifyAttestationApple.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationApple(); // 验证 Apple 类型的证明响应
 * ```
 * >查看定义:@see {@link verifyAttestationApple}
 */
declare module './verifications/verifyAttestationApple.js' {
    export * from './verifications/verifyAttestationApple.js';
}

// ================================= verifyAttestationFIDOU2F.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationFIDOU2F(); // 使用 'fido-u2f' 格式验证认证(Attestation)响应
 * ```
 * >查看定义:@see {@link verifyAttestationFIDOU2F}
 */
declare module './verifications/verifyAttestationFIDOU2F.js' {
    export * from './verifications/verifyAttestationFIDOU2F.js';
}

// ================================= verifyAttestationPacked.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationPacked(); // 验证格式为 'packed' 的 attestation 响应
 * ```
 * >查看定义:@see {@link verifyAttestationPacked}
 */
declare module './verifications/verifyAttestationPacked.js' {
    export * from './verifications/verifyAttestationPacked.js';
}

// ================================= verifyAttestationTPM.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationTPM(); // 验证TPM认证器返回的attestation陈述,确保其符合 FIDO2 规范
 * ```
 * >查看定义:@see {@link verifyAttestationTPM}
 */
declare module './verifications/verifyAttestationTPM.js' {
    export * from './verifications/verifyAttestationTPM.js';
}

// ================================= verifications模块导出 =================================
/**
 * ```js
 * // 模块导出内容:
 * verifyAttestationAndroidKey();       // 验证格式为 'android-key' 的 attestation 响应
 * verifyAttestationAndroidSafetyNet(); // 验证格式为 'android-safetynet' 的证明响应
 * verifyAttestationApple();            // 验证 Apple 类型的证明响应
 * verifyAttestationFIDOU2F();          // 使用 'fido-u2f' 格式验证认证(Attestation)响应
 * verifyAttestationPacked();           // 验证格式为 'packed' 的 attestation 响应
 * verifyAttestationTPM(); // 验证TPM认证器返回的attestation陈述,确保其符合 FIDO2 规范
 * ```
 * >查看定义:@see {@link verifyAttestationAndroidKey}、{@link verifyAttestationAndroidSafetyNet}、
 * {@link verifyAttestationApple}、{@link verifyAttestationFIDOU2F}、{@link verifyAttestationPacked}、
 * {@link verifyAttestationTPM}
 */
declare module './verifications/index.js' {
    export * from './verifyAttestationAndroidKey.js';
    export * from './verifyAttestationAndroidSafetyNet.js';
    export * from './verifyAttestationApple.js';
    export * from './verifyAttestationFIDOU2F.js';
    export * from './verifyAttestationPacked.js';
    export * from './verifyAttestationTPM.js';
}

// ================================= 整体导出入口 =================================
/**
 *
 * 验证器注册处理模块函数:
 * ```js
 * generateRegistrationOptions();              // 生成用于身份验证器注册的参数
 * verifyRegistrationResponse();               // 验证用户是否合法地完成了注册流程
 * const supportedCOSEAlgorithmIdentifiers=[]; // 支持的加密算法标识符
 * ```
 * >查看定义:@see {@link supportedCOSEAlgorithmIdentifiers}、{@link generateRegistrationOptions}、
 * {@link verifyRegistrationResponse}
 */
declare module './index.js' {
    export * from './registration.js';
}