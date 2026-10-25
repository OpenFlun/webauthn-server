/**
 * COSE 通用参数和密钥参数标识
 * @enum {number}
 * - 查看定义:@see {@link COSEKEYS}
 * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 */
const COSEKEYS = {
    kty: 1, 1: 'kty', alg: 3, 3: 'alg', crv: -1, '-1': 'crv',
    x: -2, '-2': 'x', y: -3, '-3': 'y',
    n: -1, '-1': 'n', // 注意:与 crv 共用 -1,这是 COSE 规范的设计
    e: -2, '-2': 'e'
};
/**
 * COSE 密钥类型
 * @enum {number}
 * - 查看定义:@see {@link COSEKTY}
 * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
const COSEKTY = { OKP: 1, 1: 'OKP', EC2: 2, 2: 'EC2', RSA: 3, 3: 'RSA' };

/**
 * COSE 椭圆曲线参数
 * @enum {number}
 * - 查看定义:@see {@link COSECRV}
 * @see https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */
const COSECRV = {
    P256: 1, 1: 'P256', P384: 2, 2: 'P384', P521: 3, 3: 'P521',
    ED25519: 6, 6: 'ED25519', SECP256K1: 8, 8: 'SECP256K1',
};

/**
 * COSE 算法标识
 * @enum {number}
 * - 查看定义:@see {@link COSEALG}
 * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
const COSEALG = {
    ES256: -7, '-7': 'ES256', EdDSA: -8, '-8': 'EdDSA',
    ES384: -35, '-35': 'ES384', ES512: -36, '-36': 'ES512',
    PS256: -37, '-37': 'PS256', PS384: -38, '-38': 'PS384', PS512: -39, '-39': 'PS512',
    ES256K: -47, '-47': 'ES256K',
    RS256: -257, '-257': 'RS256', RS384: -258, '-258': 'RS384', RS512: -259, '-259': 'RS512',
    RS1: -65535, '-65535': 'RS1'
};

/**
 * 判断给定的 COSE 公钥是否为 OKP 密钥对(类型守卫)
 * - 查看定义:@see {@link isCOSEPublicKeyOKP}
 * @param {Map<number, number>} cosePublicKey - 解码后的 COSE 公钥映射
 * @returns {boolean} 如果是 OKP 密钥则返回 true
 */
const isCOSEPublicKeyOKP = cosePublicKey => {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    return isCOSEKty(kty) && kty === COSEKTY.OKP;
};

/**
 * 判断给定的 COSE 公钥是否为 EC2 密钥对(类型守卫)
 * - 查看定义:@see {@link isCOSEPublicKeyEC2}
 * @param {Map<number, number>} cosePublicKey - 解码后的 COSE 公钥映射
 * @returns {boolean} 如果是 EC2 密钥则返回 true
 */
const isCOSEPublicKeyEC2 = cosePublicKey => {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    return isCOSEKty(kty) && kty === COSEKTY.EC2;
};

/**
 * 判断给定的 COSE 公钥是否为 RSA 密钥对(类型守卫)
 * - 查看定义:@see {@link isCOSEPublicKeyRSA}
 * @param {Map<number, number>} cosePublicKey - 解码后的 COSE 公钥映射
 * @returns {boolean} 如果是 RSA 密钥则返回 true
 */
const isCOSEPublicKeyRSA = cosePublicKey => {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    return isCOSEKty(kty) && kty === COSEKTY.RSA;
};
/**
 * 检查给定值是否为有效的 COSE 密钥类型(kty)
 * - 查看定义:@see {@link isCOSEKty}
 * @param {number} kty - 待检查的密钥类型值
 * @returns {boolean} 若为有效 COSE 密钥类型则返回 true
 */
const isCOSEKty = kty => {
    return Object.values(COSEKTY).indexOf(kty) >= 0;
};
/**
 * 检查给定值是否为有效的 COSE 曲线(crv)
 * - 查看定义:@see {@link isCOSECrv}
 * @param {number} crv - 待检查的曲线值
 * @returns {boolean} 若为有效 COSE 曲线则返回 true
 */
const isCOSECrv = crv => {
    return Object.values(COSECRV).indexOf(crv) >= 0;
};

/**
 * 检查给定值是否为有效的 COSE 算法(alg)
 * - 查看定义:@see {@link isCOSEAlg}
 * @param {number} alg - 待检查的算法值
 * @returns {boolean} 若为有效 COSE 算法则返回 true
 */
const isCOSEAlg = alg => {
    return Object.values(COSEALG).indexOf(alg) >= 0;
};

export {
    COSEKEYS, COSEKTY, COSECRV, COSEALG,
    isCOSEPublicKeyOKP, isCOSEPublicKeyEC2, isCOSEPublicKeyRSA, isCOSEKty, isCOSECrv, isCOSEAlg
};