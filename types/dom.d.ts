/**
 * 请勿修改这些文件!
 *
 * 这些文件是从 **types** 包中复制的,要更新此文件,请修改对应源文件,
 * 然后从 monorepo 根目录运行以下命令:
 *
 * deno task codegen:types
 */
/**
 * 根据 TypeScript@5.6.3 生成
 * 重新生成请从包根目录运行:
 * deno task extract-dom-types
 */
/**
 * 仅在安全上下文中可用;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse)
 */
export interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData) */
    readonly authenticatorData: ArrayBuffer;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse/signature) */
    readonly signature: ArrayBuffer;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse/userHandle) */
    readonly userHandle: ArrayBuffer | null;
}

/**
 * 仅在安全上下文中可用;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse)
 */
export interface AuthenticatorAttestationResponse extends AuthenticatorResponse {
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse/attestationObject) */
    readonly attestationObject: ArrayBuffer;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse/getAuthenticatorData) */
    getAuthenticatorData(): ArrayBuffer;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse/getPublicKey) */
    getPublicKey(): ArrayBuffer | null;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse/getPublicKeyAlgorithm) */
    getPublicKeyAlgorithm(): COSEAlgorithmIdentifier;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse/getTransports) */
    getTransports(): string[];
}

export interface AuthenticationExtensionsClientInputs {
    appid?: string;
    credProps?: boolean;
    hmacCreateSecret?: boolean;
    minPinLength?: boolean;
}

export interface AuthenticationExtensionsClientOutputs {
    appid?: boolean;
    credProps?: CredentialPropertiesOutput;
    hmacCreateSecret?: boolean;
}

export interface AuthenticatorSelectionCriteria {
    authenticatorAttachment?: AuthenticatorAttachment;
    requireResidentKey?: boolean;
    residentKey?: ResidentKeyRequirement;
    userVerification?: UserVerificationRequirement;
}

/**
 * 当前上下文中可用的基本密码学功能,允许访问密码学安全的随机数生成器和密码学原语;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/Crypto)
 */
export interface Crypto {
    /**
     * 仅在安全上下文中可用;
     *
     * [MDN 参考](https://developer.mozilla.org/docs/Web/API/Crypto/subtle)
     */
    readonly subtle: SubtleCrypto;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/Crypto/getRandomValues) */
    getRandomValues<T extends ArrayBufferView | null>(array: T): T;
    /**
     * 仅在安全上下文中可用;
     *
     * [MDN 参考](https://developer.mozilla.org/docs/Web/API/Crypto/randomUUID)
     */
    randomUUID(): `${string}-${string}-${string}-${string}-${string}`;
}

/**
 * 仅在安全上下文中可用;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential)
 */
export interface PublicKeyCredential extends Credential {
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential/authenticatorAttachment) */
    readonly authenticatorAttachment: string | null;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential/rawId) */
    readonly rawId: ArrayBuffer;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential/response) */
    readonly response: AuthenticatorResponse;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential/getClientExtensionResults) */
    getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
}

export interface PublicKeyCredentialCreationOptions {
    attestation?: AttestationConveyancePreference;
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    challenge: BufferSource;
    excludeCredentials?: PublicKeyCredentialDescriptor[];
    extensions?: AuthenticationExtensionsClientInputs;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    rp: PublicKeyCredentialRpEntity;
    timeout?: number;
    user: PublicKeyCredentialUserEntity;
}

export interface PublicKeyCredentialDescriptor {
    id: BufferSource;
    transports?: AuthenticatorTransport[];
    type: PublicKeyCredentialType;
}

export interface PublicKeyCredentialParameters {
    alg: COSEAlgorithmIdentifier;
    type: PublicKeyCredentialType;
}

export interface PublicKeyCredentialRequestOptions {
    allowCredentials?: PublicKeyCredentialDescriptor[];
    challenge: BufferSource;
    extensions?: AuthenticationExtensionsClientInputs;
    rpId?: string;
    timeout?: number;
    userVerification?: UserVerificationRequirement;
}

export interface PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
    displayName: string;
    id: BufferSource;
}

/**
 * 仅在安全上下文中可用;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorResponse)
 */
export interface AuthenticatorResponse {
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/AuthenticatorResponse/clientDataJSON) */
    readonly clientDataJSON: ArrayBuffer;
}

export interface CredentialPropertiesOutput {
    rk?: boolean;
}

/**
 * 此 Web Crypto API 接口提供许多低级密码学函数,可通过窗口上下文中的 Crypto.subtle 属性访问(通过 Window.crypto);
 * 仅在安全上下文中可用;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto)
 */
export interface SubtleCrypto {
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/decrypt) */
    decrypt(
        algorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams,
        key: CryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/deriveBits) */
    deriveBits(
        algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params,
        baseKey: CryptoKey,
        length: number
    ): Promise<ArrayBuffer>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/deriveKey) */
    deriveKey(
        algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params,
        baseKey: CryptoKey,
        derivedKeyType: AlgorithmIdentifier | AesDerivedKeyParams | HmacImportParams | HkdfParams | Pbkdf2Params,
        extractable: boolean,
        keyUsages: KeyUsage[]
    ): Promise<CryptoKey>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/digest) */
    digest(algorithm: AlgorithmIdentifier, data: BufferSource): Promise<ArrayBuffer>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/encrypt) */
    encrypt(
        algorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams,
        key: CryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/exportKey) */
    exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
    exportKey(format: Exclude<KeyFormat, "jwk">, key: CryptoKey): Promise<ArrayBuffer>;
    exportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/generateKey) */
    generateKey(
        algorithm: "Ed25519",
        extractable: boolean,
        keyUsages: ReadonlyArray<"sign" | "verify">
    ): Promise<CryptoKeyPair>;
    generateKey(
        algorithm: RsaHashedKeyGenParams | EcKeyGenParams,
        extractable: boolean,
        keyUsages: ReadonlyArray<KeyUsage>
    ): Promise<CryptoKeyPair>;
    generateKey(
        algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params,
        extractable: boolean,
        keyUsages: ReadonlyArray<KeyUsage>
    ): Promise<CryptoKey>;
    generateKey(
        algorithm: AlgorithmIdentifier,
        extractable: boolean,
        keyUsages: KeyUsage[]
    ): Promise<CryptoKeyPair | CryptoKey>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/importKey) */
    importKey(
        format: "jwk",
        keyData: JsonWebKey,
        algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm,
        extractable: boolean,
        keyUsages: ReadonlyArray<KeyUsage>
    ): Promise<CryptoKey>;
    importKey(
        format: Exclude<KeyFormat, "jwk">,
        keyData: BufferSource,
        algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm,
        extractable: boolean,
        keyUsages: KeyUsage[]
    ): Promise<CryptoKey>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/sign) */
    sign(
        algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
        key: CryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/unwrapKey) */
    unwrapKey(
        format: KeyFormat,
        wrappedKey: BufferSource,
        unwrappingKey: CryptoKey,
        unwrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams,
        unwrappedKeyAlgorithm:
            AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm,
        extractable: boolean,
        keyUsages: KeyUsage[]
    ): Promise<CryptoKey>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/verify) */
    verify(
        algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
        key: CryptoKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean>;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/wrapKey) */
    wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingKey: CryptoKey,
        wrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams
    ): Promise<ArrayBuffer>;
}

/**
 * 仅在安全上下文中可用;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/Credential)
 */
export interface Credential {
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/Credential/id) */
    readonly id: string;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/Credential/type) */
    readonly type: string;
}

export interface PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
    id?: string;
}

export interface PublicKeyCredentialEntity {
    name: string;
}

export interface RsaOaepParams extends Algorithm {
    label?: BufferSource;
}

export interface AesCtrParams extends Algorithm {
    counter: BufferSource;
    length: number;
}

export interface AesCbcParams extends Algorithm {
    iv: BufferSource;
}

export interface AesGcmParams extends Algorithm {
    additionalData?: BufferSource;
    iv: BufferSource;
    tagLength?: number;
}

/**
 * Web Crypto API 的 CryptoKey 字典表示一个加密密钥;
 * 仅在安全上下文中可用;
 *
 * [MDN 参考](https://developer.mozilla.org/docs/Web/API/CryptoKey)
 */
export interface CryptoKey {
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/CryptoKey/algorithm) */
    readonly algorithm: KeyAlgorithm;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/CryptoKey/extractable) */
    readonly extractable: boolean;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/CryptoKey/type) */
    readonly type: KeyType;
    /** [MDN 参考](https://developer.mozilla.org/docs/Web/API/CryptoKey/usages) */
    readonly usages: KeyUsage[];
}

export interface EcdhKeyDeriveParams extends Algorithm {
    public: CryptoKey;
}

export interface HkdfParams extends Algorithm {
    hash: HashAlgorithmIdentifier;
    info: BufferSource;
    salt: BufferSource;
}

export interface Pbkdf2Params extends Algorithm {
    hash: HashAlgorithmIdentifier;
    iterations: number;
    salt: BufferSource;
}

export interface AesDerivedKeyParams extends Algorithm {
    length: number;
}

export interface HmacImportParams extends Algorithm {
    hash: HashAlgorithmIdentifier;
    length?: number;
}

export interface JsonWebKey {
    alg?: string, crv?: string, d?: string, dp?: string, dq?: string, e?: string;
    ext?: boolean;
    k?: string, key_ops?: string[], kty?: string, n?: string;
    oth?: RsaOtherPrimesInfo[];
    p?: string, q?: string, qi?: string, use?: string, x?: string, y?: string;
}

export interface CryptoKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export interface RsaHashedKeyGenParams extends RsaKeyGenParams {
    hash: HashAlgorithmIdentifier;
}

export interface EcKeyGenParams extends Algorithm {
    namedCurve: NamedCurve;
}

export interface AesKeyGenParams extends Algorithm {
    length: number;
}

export interface HmacKeyGenParams extends Algorithm {
    hash: HashAlgorithmIdentifier;
    length?: number;
}

export interface RsaHashedImportParams extends Algorithm {
    hash: HashAlgorithmIdentifier;
}

export interface EcKeyImportParams extends Algorithm {
    namedCurve: NamedCurve;
}

export interface AesKeyAlgorithm extends KeyAlgorithm {
    length: number;
}

export interface RsaPssParams extends Algorithm {
    saltLength: number;
}

export interface EcdsaParams extends Algorithm {
    hash: HashAlgorithmIdentifier;
}

export interface Algorithm {
    name: string;
}

export interface KeyAlgorithm {
    name: string;
}

export interface RsaOtherPrimesInfo {
    d?: string, r?: string, t?: string;
}

export interface RsaKeyGenParams extends Algorithm {
    modulusLength: number;
    publicExponent: BigInteger;
}

export type AttestationConveyancePreference = "direct" | "enterprise" | "indirect" | "none";
export type AuthenticatorTransport = "ble" | "hybrid" | "internal" | "nfc" | "usb";
export type COSEAlgorithmIdentifier = number;
export type ResidentKeyRequirement = "discouraged" | "preferred" | "required";
export type UserVerificationRequirement = "discouraged" | "preferred" | "required";
export type AuthenticatorAttachment = "cross-platform" | "platform";
export type BufferSource = ArrayBufferView | ArrayBuffer;
export type PublicKeyCredentialType = "public-key";
export type AlgorithmIdentifier = Algorithm | string;
export type KeyUsage = "decrypt" | "deriveBits" | "deriveKey" | "encrypt" | "sign" | "unwrapKey" | "verify" | "wrapKey";
export type KeyFormat = "jwk" | "pkcs8" | "raw" | "spki";
export type KeyType = "private" | "public" | "secret";
export type HashAlgorithmIdentifier = AlgorithmIdentifier;
export type NamedCurve = string;
export type BigInteger = Uint8Array;