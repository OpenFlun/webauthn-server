import { decodeAuthenticatorExtensions, } from './decodeAuthenticatorExtensions.js';
import { toDataView, fromHex, areEqual, decodeFirst, encode } from './iso/index.js';

/**
 * 便于在测试时对返回值进行桩(stub)操作
 * - 查看定义:@see {@link _parseAuthenticatorDataInternals}
 * @ignore 不要将此导出包含在文档输出中
 * @type {{ stubThis: <T>(value: T) => T }}
 */
const _parseAuthenticatorDataInternals = { stubThis: value => value };

/**
 * 解析认证数据(Attestation 中包含的 authData 缓冲区)
 * - 查看定义:@see {@link parseAuthenticatorData}
 *
 * @param {BufferSource} authData - 认证器数据字节序列
 * @returns {{
 *   rpIdHash: Uint8Array,
 *   flagsBuf: Uint8Array,
 *   flags: { up: boolean, uv: boolean, be: boolean, bs: boolean, at: boolean, ed: boolean, flagsInt: number },
 *   counter: number,
 *   counterBuf: Uint8Array,
 *   aaguid?: Uint8Array,
 *   credentialID?: Uint8Array,
 *   credentialPublicKey?: Uint8Array,
 *   extensionsData?: AuthenticationExtensionsAuthenticatorOutputs,
 *   extensionsDataBuffer?: Uint8Array
 * }}
 */
const parseAuthenticatorData = authData => {
    if (authData.byteLength < 37) throw new Error(`认证数据长度为 ${authData.byteLength} 字节,预期至少 37 字节`);

    let pointer = 0;
    const dataView = toDataView(authData), rpIdHash = authData.slice(pointer, (pointer += 32)),
        flagsBuf = authData.slice(pointer, (pointer += 1)), flagsInt = flagsBuf[0];

    // 标志位可参考:
    // https://www.w3.org/TR/webauthn-2/#flags
    const flags = {
        up: !!(flagsInt & (1 << 0)), // 用户存在(User Presence)
        uv: !!(flagsInt & (1 << 2)), // 用户已验证(User Verified)
        be: !!(flagsInt & (1 << 3)), // 备份可用性(Backup Eligibility)
        bs: !!(flagsInt & (1 << 4)), // 备份状态(Backup State)
        at: !!(flagsInt & (1 << 6)), // 存在证明凭证数据(Attested Credential Data Present)
        ed: !!(flagsInt & (1 << 7)), // 存在扩展数据(Extension Data Present)
        flagsInt,
    };

    const counterBuf = authData.slice(pointer, pointer + 4), counter = dataView.getUint32(pointer, false);
    pointer += 4;

    let aaguid = undefined, credentialID = undefined, credentialPublicKey = undefined;
    if (flags.at) {
        aaguid = authData.slice(pointer, (pointer += 16));

        const credIDLen = dataView.getUint16(pointer);
        pointer += 2, credentialID = authData.slice(pointer, (pointer += credIDLen));

        /**
         * Firefox 117 在使用 EdDSA (-8) 作为公钥时错误地对 authData 进行了 CBOR 编码;
         * 一个"3 项的映射"(0xa3)本应是"4 项的映射"(0xa4),如果手动修正这一个字节,
         * 则 authData 有很大概率可以被正确解析;
         *
         * 该浏览器版本还错误地使用了字符串标签 "OKP" 和 "Ed25519" 来代替它们各自的整数表示(kty 和 crv);
         * 这就是为什么下面的十六进制中的 COSE 公钥看起来如此奇怪;
         */
        // 解码后应为 `{ 1: "OKP",3: -8,-1: "Ed25519" }`(缺少键 -2,即 COSEKEYS.x)
        const badEdDSACBOR = fromHex('a301634f4b500327206745643235353139'),
            bytesAtCurrentPosition = authData.slice(pointer, pointer + badEdDSACBOR.byteLength);
        let foundBadCBOR = false;
        // 将错误的 CBOR 0xa3 改为 0xa4,以便能识别出凭证公钥
        if (areEqual(badEdDSACBOR, bytesAtCurrentPosition)) foundBadCBOR = true, authData[pointer] = 0xa4;

        // 解码缓冲区中的下一个 CBOR 项,然后将其重新编码回 Buffer
        const firstDecoded = decodeFirst(authData.slice(pointer)),
            firstEncoded = Uint8Array.from(
                /**
                 * 此处通过 `as unknown` 强制转换为 `Map`,因为 TypeScript 无法定义具有离散键和已知类型属性的 Map,
                 * 且 CBOR 库通常将 CBOR 主类型 5 解析为 `Map`,因为键可以是数字,一个 `COSEPublicKey` 可以广义地
                 * 理解为"一个键为数字、值为数字或字节的 Map",如果这个假设不成立,后续验证的其他部分将会失败,
                 * 因此在此处进行这样的转换是安全的;
                 */
                encode(firstDecoded),
            );

        // 恢复刚才修改的字节,使 `authData` 与传入时一致,避免破坏签名验证
        if (foundBadCBOR) authData[pointer] = 0xa3;
        credentialPublicKey = firstEncoded, pointer += firstEncoded.byteLength;
    }

    let extensionsData = undefined, extensionsDataBuffer = undefined;
    if (flags.ed) {
        const firstDecoded = decodeFirst(authData.slice(pointer));

        extensionsDataBuffer = Uint8Array.from(encode(firstDecoded));
        extensionsData = decodeAuthenticatorExtensions(extensionsDataBuffer);
        pointer += extensionsDataBuffer.byteLength;
    }

    // 指针应位于认证数据的末尾,否则说明传入了多余的数据
    if (authData.byteLength > pointer) throw new Error('解析认证数据时检测到剩余字节');

    return _parseAuthenticatorDataInternals.stubThis({
        rpIdHash, flagsBuf, flags, counter, counterBuf,
        aaguid, credentialID, credentialPublicKey, extensionsData, extensionsDataBuffer
    });
};

export { _parseAuthenticatorDataInternals, parseAuthenticatorData };