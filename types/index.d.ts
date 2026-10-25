/**
 * 请勿修改这些文件!
 *
 * 这些文件是从 **types** 包中复制的,要更新此文件,请修改对应源文件,
 * 然后从 monorepo 根目录运行以下命令:
 *
 * deno task codegen:types
 */
import type {
    AttestationConveyancePreference, AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs,
    AuthenticatorAssertionResponse, AuthenticatorAttachment, AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    COSEAlgorithmIdentifier, PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    UserVerificationRequirement
} from './dom.js';

export type {
    AttestationConveyancePreference, AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs,
    AuthenticatorAssertionResponse, AuthenticatorAttachment, AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport, COSEAlgorithmIdentifier, Crypto, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, ResidentKeyRequirement, UserVerificationRequirement
} from './dom.js';

/**
 * PublicKeyCredentialCreationOptions 的变体,适合通过 JSON 传输到浏览器,
 * 最终传入浏览器的 navigator.credentials.create(...) 方法;
 *
 * 当 WebAuthn L3 类型最终被纳入语言时,应被官方的 TypeScript DOM 类型取代:
 *
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptionsjson
 */
export interface PublicKeyCredentialCreationOptionsJSON {
    rp: PublicKeyCredentialRpEntity;
    user: PublicKeyCredentialUserEntityJSON;
    challenge: Base64URLString;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    timeout?: number;
    excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    hints?: PublicKeyCredentialHint[];
    attestation?: AttestationConveyancePreference;
    attestationFormats?: AttestationFormat[];
    extensions?: AuthenticationExtensionsClientInputs;
}

/**
 * PublicKeyCredentialRequestOptions 的变体,适合通过 JSON 传输到浏览器,
 * 最终传入浏览器的 navigator.credentials.get(...) 方法;
 */
export interface PublicKeyCredentialRequestOptionsJSON {
    challenge: Base64URLString;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptorJSON[];
    userVerification?: UserVerificationRequirement;
    hints?: PublicKeyCredentialHint[];
    extensions?: AuthenticationExtensionsClientInputs;
}

/**
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptorjson
 */
export interface PublicKeyCredentialDescriptorJSON {
    id: Base64URLString;
    type: PublicKeyCredentialType;
    transports?: AuthenticatorTransportFuture[];
}

/**
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentityjson
 */
export interface PublicKeyCredentialUserEntityJSON {
    id: string;
    name: string;
    displayName: string;
}

/**
 * navigator.credentials.create() 返回的值
 */
export interface RegistrationCredential extends PublicKeyCredentialFuture {
    response: AuthenticatorAttestationResponseFuture;
}

/**
 * 略微修改的 RegistrationCredential,简化处理在浏览器中经过 Base64URL 编码的 ArrayBuffer,
 * 以便以 JSON 形式发送到服务器;
 *
 * https://w3c.github.io/webauthn/#dictdef-registrationresponsejson
 */
export interface RegistrationResponseJSON {
    id: Base64URLString;
    rawId: Base64URLString;
    response: AuthenticatorAttestationResponseJSON;
    authenticatorAttachment?: AuthenticatorAttachment;
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
    type: PublicKeyCredentialType;
}

/**
 * navigator.credentials.get() 返回的值
 */
export interface AuthenticationCredential extends PublicKeyCredentialFuture {
    response: AuthenticatorAssertionResponse;
}

/**
 * 略微修改的 AuthenticationCredential,简化处理在浏览器中经过 Base64URL 编码的 ArrayBuffer,
 * 以便以 JSON 形式发送到服务器;
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson
 */
export interface AuthenticationResponseJSON {
    id: Base64URLString;
    rawId: Base64URLString;
    response: AuthenticatorAssertionResponseJSON;
    authenticatorAttachment?: AuthenticatorAttachment;
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
    type: PublicKeyCredentialType;
}

/**
 * 略微修改的 AuthenticatorAttestationResponse,简化处理在浏览器中经过 Base64URL 编码的 ArrayBuffer,
 * 以便以 JSON 形式发送到服务器;
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticatorattestationresponsejson
 */
export interface AuthenticatorAttestationResponseJSON {
    clientDataJSON: Base64URLString;
    attestationObject: Base64URLString;
    authenticatorData?: Base64URLString;
    transports?: AuthenticatorTransportFuture[];
    publicKeyAlgorithm?: COSEAlgorithmIdentifier;
    publicKey?: Base64URLString;
}

/**
 * 略微修改的 AuthenticatorAssertionResponse,简化处理在浏览器中经过 Base64URL 编码的 ArrayBuffer,
 * 以便以 JSON 形式发送到服务器;
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticatorassertionresponsejson
 */
export interface AuthenticatorAssertionResponseJSON {
    clientDataJSON: Base64URLString;
    authenticatorData: Base64URLString;
    signature: Base64URLString;
    userHandle?: Base64URLString;
}

/**
 * 验证认证响应所需的公钥凭证信息
 */
export type WebAuthnCredential = {
    id: Base64URLString;
    publicKey: Uint8Array_;
    counter: number;
    transports?: AuthenticatorTransportFuture[];
};

/**
 * 表示这不只是一个普通字符串,而是一个 Base64URL 编码的字符串
 */
export type Base64URLString = string;

/**
 * TypeScript DOM 库中的 AuthenticatorAttestationResponse 已过时(最高到 v3.9.7);
 * 此处维护一个增强版本,以便在 WebAuthn 规范演进时实现附加属性;
 *
 * 参见 https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse
 *
 * 标记为可选的属性并非在所有浏览器中都支持;
 */
export interface AuthenticatorAttestationResponseFuture extends AuthenticatorAttestationResponse {
    getTransports(): AuthenticatorTransportFuture[];
}

/**
 * TypeScript 的 `AuthenticatorTransport` 的超集,包含对最新传输方式的支持;
 * 最终当 TypeScript 更新(大约在 4.6.3 之后)知晓这些传输方式时,应被 TypeScript 的类型取代;
 */
export type AuthenticatorTransportFuture = 'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

/**
 * TypeScript 的 `PublicKeyCredentialDescriptor` 的超集,知晓最新的传输方式;
 * 最终当 TypeScript 更新(大约在 4.6.3 之后)知晓这些传输方式时,应被 TypeScript 的类型取代;
 */
export interface PublicKeyCredentialDescriptorFuture extends Omit<PublicKeyCredentialDescriptor, 'transports'> {
    transports?: AuthenticatorTransportFuture[];
}

/** */
export type PublicKeyCredentialJSON = RegistrationResponseJSON | AuthenticationResponseJSON;

/**
 * TypeScript 的 `PublicKeyCredential` 的超集,知晓即将到来的 WebAuthn 特性;
 */
export interface PublicKeyCredentialFuture extends PublicKeyCredential {
    type: PublicKeyCredentialType;
    isConditionalMediationAvailable?(): Promise<boolean>;
    parseCreationOptionsFromJSON?(options: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions;
    parseRequestOptionsFromJSON?(options: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions;
    toJSON?(): PublicKeyCredentialJSON;
}

/**
 * 根据验证器数据中第 3 位("备份资格")定义的两种凭证类型:
 * - `"singleDevice"` 凭证永远不会被备份
 * - `"multiDevice"` 凭证可以被备份
 */
export type CredentialDeviceType = 'singleDevice' | 'multiDevice';

/**
 * 依赖方可以在注册时传递给浏览器的验证器类别;支持这些值的浏览器可以优化其模态体验;
 * 让用户从特定的注册流程开始:
 *
 * - `hybrid`:移动设备上的平台验证器
 * - `security-key`:可通过 USB 或 NFC 连接在多个设备上使用的便携式 FIDO2 验证器
 * - `client-device`:调用 WebAuthn 的设备;通常与平台验证器同义
 *
 * 参见 https://w3c.github.io/webauthn/#enumdef-publickeycredentialhint
 *
 * 这些值比 `authenticatorAttachment` 宽松
 */
export type PublicKeyCredentialHint = 'hybrid' | 'security-key' | 'client-device';

/**
 * 验证对象的 `fmt` 取值
 *
 * 参见 https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids
 */
export type AttestationFormat = 'fido-u2f' | 'packed' | 'android-safetynet' | 'android-key' | 'tpm' | 'apple' | 'none';

/**
 * 在 TypeScript 5.7 之前等同于 `Uint8Array`,在 TypeScript 5.7 及之后等同于 `Uint8Array<ArrayBuffer>`;
 *
 * **背景**
 *
 * `Uint8Array` 在 TypeScript 5.7 中成为泛型类型,要求从 Deno 2.2 开始将简单定义为 `Uint8Array` 的类型
 * 重构为 `Uint8Array<ArrayBuffer>`;
 * 然而在 Deno 2.1.x 及更早版本中 `Uint8Array` _不是_ 泛型,因此此类型有助于弥合这一差距;
 *
 * 灵感来自 Deno 的标准库:
 *
 * https://github.com/denoland/std/blob/b5a5fe4f96b91c1fe8dba5cc0270092dd11d3287/bytes/_types.ts#L11
 */
export type Uint8Array_ = ReturnType<Uint8Array['slice']>;