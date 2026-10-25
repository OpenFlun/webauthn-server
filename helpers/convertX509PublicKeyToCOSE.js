import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { ECParameters, id_ecPublicKey, id_secp256r1, id_secp384r1 } from '@peculiar/asn1-ecc';
import { id_rsaEncryption, RSAPublicKey } from '@peculiar/asn1-rsa';
import { COSECRV, COSEKEYS, COSEKTY } from './cose.js';
import { mapX509SignatureAlgToCOSEAlg } from './mapX509SignatureAlgToCOSEAlg.js';

/**
 * 从 X.509 证书(DER 格式)中提取公钥,并将其转换为 COSE 公钥结构
 *
 * @param {BufferSource} x509Certificate - DER 编码的 X.509 证书缓冲区
 * @returns {Map<number, number | Uint8Array>} 解析出的 COSE 公钥 Map 对象,可根据密钥类型(OKP/EC2/RSA)使用类型守卫进行细化
 * @throws 若证书格式无效或公钥类型不受支持,将抛出错误
 * - 查看定义:@see {@link convertX509PublicKeyToCOSE}
 * - {@link https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-map|COSE Key Map Specification}
 */
const convertX509PublicKeyToCOSE = x509Certificate => {
    /** @type {Map<number, number | Uint8Array>} */
    let cosePublicKey = new Map();

    /**
     * 从 X.509 证书中提取公钥
     */
    const x509 = AsnParser.parse(x509Certificate, Certificate), { tbsCertificate } = x509,
        { subjectPublicKeyInfo, signature: _tbsSignature } = tbsCertificate, signatureAlgorithm = _tbsSignature.algorithm,
        publicKeyAlgorithmID = subjectPublicKeyInfo.algorithm.algorithm;

    if (publicKeyAlgorithmID === id_ecPublicKey) {
        if (!subjectPublicKeyInfo.algorithm.parameters) throw new Error('证书公钥缺少参数(EC2)');

        const ecParameters = AsnParser.parse(new Uint8Array(subjectPublicKeyInfo.algorithm.parameters), ECParameters),
            { namedCurve } = ecParameters;
        let crv = -999;

        if (namedCurve === id_secp256r1) crv = COSECRV.P256;
        else if (namedCurve === id_secp384r1) crv = COSECRV.P384;
        else throw new Error(`证书公钥包含意外的 namedCurve: ${namedCurve} (EC2)`);

        const subjectPublicKey = new Uint8Array(subjectPublicKeyInfo.subjectPublicKey);
        let x, y;

        if (subjectPublicKey[0] === 0x04) {
            // 公钥采用"未压缩格式",将剩余字节平分为两半
            let pointer = 1;
            const halfLength = (subjectPublicKey.length - 1) / 2;
            x = subjectPublicKey.slice(pointer, pointer += halfLength);
            y = subjectPublicKey.slice(pointer);
        }
        else throw new Error('暂未支持"压缩格式"公钥的处理');

        const coseEC2PubKey = new Map();
        coseEC2PubKey.set(COSEKEYS.kty, COSEKTY.EC2);
        coseEC2PubKey.set(COSEKEYS.alg, mapX509SignatureAlgToCOSEAlg(signatureAlgorithm));
        coseEC2PubKey.set(COSEKEYS.crv, crv);
        coseEC2PubKey.set(COSEKEYS.x, x);
        coseEC2PubKey.set(COSEKEYS.y, y);

        cosePublicKey = coseEC2PubKey;
    } else if (publicKeyAlgorithmID === id_rsaEncryption) {
        /**
         * RSA 公钥
         */
        const rsaPublicKey = AsnParser.parse(subjectPublicKeyInfo.subjectPublicKey, RSAPublicKey),
            coseRSAPubKey = new Map();

        coseRSAPubKey.set(COSEKEYS.kty, COSEKTY.RSA);
        coseRSAPubKey.set(COSEKEYS.alg, mapX509SignatureAlgToCOSEAlg(signatureAlgorithm));
        coseRSAPubKey.set(COSEKEYS.n, new Uint8Array(rsaPublicKey.modulus));
        coseRSAPubKey.set(COSEKEYS.e, new Uint8Array(rsaPublicKey.publicExponent));

        cosePublicKey = coseRSAPubKey;
    }
    else throw new Error(`证书公钥包含非预期的算法 ID: ${publicKeyAlgorithmID}`);

    return cosePublicKey;
}

export { convertX509PublicKeyToCOSE };