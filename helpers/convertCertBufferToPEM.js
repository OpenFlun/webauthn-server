import { isBase64URL, toBase64, isBase64, fromBuffer } from './iso/index.js';

/**
 * 将证书缓冲区转换为 OpenSSL 兼容的 PEM 文本格式;
 * - 查看定义:@see {@link convertCertBufferToPEM}
 * @param {string|BufferSource} certBuffer - 证书缓冲区,支持 base64 字符串、base64url 字符串或二进制数据
 * @returns {string} OpenSSL 兼容的 PEM 格式证书字符串
 */
const convertCertBufferToPEM = certBuffer => {
    let b64cert;
    /**
     * 获取证书缓冲区的 Base64 表示形式
     */
    if (typeof certBuffer === 'string') {
        if (isBase64URL(certBuffer)) b64cert = toBase64(certBuffer);
        else if (isBase64(certBuffer)) b64cert = certBuffer;
        else throw new Error('证书不是有效的 base64 或 base64url 字符串');
    }
    else b64cert = fromBuffer(certBuffer, 'base64');

    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
        const start = 64 * i;
        PEMKey += `${b64cert.slice(start, start + 64)}\n`;
    }
    PEMKey = `-----BEGIN CERTIFICATE-----\n${PEMKey}-----END CERTIFICATE-----\n`;
    return PEMKey;
};

export { convertCertBufferToPEM };