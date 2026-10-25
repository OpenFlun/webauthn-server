import {
    b64urlToUtf8, toBuffer, utf8Tobytes, verifyEC2, verifyRSA, convertAAGUIDToString,
    convertCertBufferToPEM, convertPEMToBytes,
    convertX509PublicKeyToCOSE, COSEKEYS, COSEKTY, COSEALG, isCOSEPublicKeyEC2,
    isCOSEPublicKeyRSA, decodeCredentialPublicKey,
    fetch, getLogger, validateCertificatePath
} from '../helpers/index.js';

import { SettingsService } from './settings.js';

// ================================= 算法数组 =================================
/**
 * 支持的签名算法数组
 * - 查看定义:@see {@link AlgSign}
 * @type {string[]}
 * @constant
 * @description
 * 算法命名规则: [曲线/算法]_[签名类型]_[哈希算法]_[编码格式]
 * 其中:
 * - secp256r1, secp256k1, secp384r1, secp512r1: 椭圆曲线
 * - ed25519: EdDSA曲线
 * - rsassa_pss: RSA-PSS填充方案
 * - rsassa_pkcsv1_5: RSA PKCS#1 v1.5填充方案
 * - ecdsa: 椭圆曲线数字签名算法
 * - eddsa: Edwards曲线数字签名算法
 * - sha256, sha384, sha512, sha1: 哈希算法
 * - raw: 原始签名输出(无ASN.1 DER编码)
 * - der: DER编码格式
 */
const AlgSign = [
    'secp256r1_ecdsa_sha256_raw',   // secp256r1曲线,ECDSA,SHA-256,原始格式
    'secp256r1_ecdsa_sha256_der',   // secp256r1曲线,ECDSA,SHA-256,DER编码
    'rsassa_pss_sha256_raw',        // RSA-PSS,SHA-256,原始格式
    'rsassa_pss_sha256_der',        // RSA-PSS,SHA-256,DER编码
    'secp256k1_ecdsa_sha256_raw',   // secp256k1曲线,ECDSA,SHA-256,原始格式
    'secp256k1_ecdsa_sha256_der',   // secp256k1曲线,ECDSA,SHA-256,DER编码
    'rsassa_pss_sha384_raw',        // RSA-PSS,SHA-384,原始格式
    'rsassa_pkcsv15_sha256_raw',    // RSA PKCS#1 v1.5,SHA-256,原始格式
    'rsassa_pkcsv15_sha384_raw',    // RSA PKCS#1 v1.5,SHA-384,原始格式
    'rsassa_pkcsv15_sha512_raw',    // RSA PKCS#1 v1.5,SHA-512,原始格式
    'rsassa_pkcsv15_sha1_raw',      // RSA PKCS#1 v1.5,SHA-1,原始格式
    'secp384r1_ecdsa_sha384_raw',   // secp384r1曲线,ECDSA,SHA-384,原始格式
    'secp512r1_ecdsa_sha256_raw',   // secp512r1曲线,ECDSA,SHA-256,原始格式
    'ed25519_eddsa_sha512_raw',     // Ed25519曲线,EdDSA,SHA-512,原始格式
];

// ================================= JWT处理 =================================
/**
 * 将 JWT 解析为 JavaScript 友好的数据结构
 * - 查看定义:@see {@link parseJWT}
 * @param {string} jwt - 原始的 JWT 字符串(三段式 base64url 编码)
 * @returns {[Record<string, unknown>, Record<string, unknown>, string]}
 *   返回一个元组:
 *   - 索引 0: 解码后的 JWT 头部(标准 JSON 对象)
 *   - 索引 1: 解码后的 JWT 载荷(标准 JSON 对象)
 *   - 索引 2: 原始签名部分(base64url 字符串)
 */
const parseJWT = jwt => {
    const parts = jwt.split('.');
    return [
        JSON.parse(b64urlToUtf8(parts[0])),
        JSON.parse(b64urlToUtf8(parts[1])),
        parts[2]
    ];
};

// ================================= 身份验证器匹配处理 =================================
/**
 * 将 ALG_SIGN 值转换为 COSE 信息
 *
 * 值来自 FIDO 预定义值注册表中的 `ALG_KEY_COSE` 定义
 * - 查看定义:@see {@link algSignToCOSEInfoMap}
 * - 参考文档:https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
 * @type {Record<string, { kty: number, alg: number, crv?: number }>}
 */
const algSignToCOSEInfoMap = {
    secp256r1_ecdsa_sha256_raw: { kty: 2, alg: -7, crv: 1 },
    secp256r1_ecdsa_sha256_der: { kty: 2, alg: -7, crv: 1 },
    rsassa_pss_sha256_raw: { kty: 3, alg: -37 },
    rsassa_pss_sha256_der: { kty: 3, alg: -37 },
    secp256k1_ecdsa_sha256_raw: { kty: 2, alg: -47, crv: 8 },
    secp256k1_ecdsa_sha256_der: { kty: 2, alg: -47, crv: 8 },
    rsassa_pss_sha384_raw: { kty: 3, alg: -38 },
    rsassa_pkcsv15_sha256_raw: { kty: 3, alg: -257 },
    rsassa_pkcsv15_sha384_raw: { kty: 3, alg: -258 },
    rsassa_pkcsv15_sha512_raw: { kty: 3, alg: -259 },
    rsassa_pkcsv15_sha1_raw: { kty: 3, alg: -65535 },
    secp384r1_ecdsa_sha384_raw: { kty: 2, alg: -35, crv: 2 },
    secp512r1_ecdsa_sha256_raw: { kty: 2, alg: -36, crv: 3 },
    ed25519_eddsa_sha512_raw: { kty: 1, alg: -8, crv: 6 },
};

/**
 * 辅助函数,以比 JSON.stringify() 更友好的方式格式化 COSEInfo
 *
 * 输入:`{ "kty": 3, "alg": -257 }`
 *
 * 输出:`"{ kty: 3, alg: -257 }"`
 *
 * @param {{ kty: number, alg: number, crv?: number }} info - COSE 信息对象
 * @returns {string} 格式化后的字符串
 */
const stringifyCOSEInfo = info => {
    const { kty, alg, crv } = info;

    let toReturn = '';
    if (kty !== COSEKTY.RSA) toReturn = `{ kty: ${kty}, alg: ${alg}, crv: ${crv} }`;
    else toReturn = `{ kty: ${kty}, alg: ${alg} }`;

    return toReturn;
};

/**
 * 将身份验证器的 attestation 陈述中的属性与 FIDO 联盟元数据服务中注册的期望值进行匹配
 * - 查看定义:@see {@link verifyAttestationWithMetadata}
 *
 * @param {Object} params - 验证参数
 * @param {Object} params.statement - 来自 MDS 的元数据陈述对象
 * @param {string[]} params.statement.authenticationAlgorithms - 支持的算法标识符列表
 * @param {Object} [params.statement.authenticatorGetInfo] - 身份验证器 GetInfo 响应
 * @param {Array<{ alg: number }>} [params.statement.authenticatorGetInfo.algorithms] - 支持的 COSE 算法列表
 * @param {BufferSource[]} params.statement.attestationRootCertificates - 信任锚证书(DER 格式)
 * @param {BufferSource} params.credentialPublicKey - 凭证公钥(COSE 编码)
 * @param {BufferSource[]} params.x5c - 认证器证书链(DER 格式,X.509)
 * @param {number} [params.attestationStatementAlg] - Attestation 陈述中声明的算法(COSE alg 值)
 * @returns {Promise<boolean>} 验证通过时返回 true,否则抛出错误
 */
const verifyAttestationWithMetadata = async ({ statement, credentialPublicKey, x5c, attestationStatementAlg, }) => {
    const {
        authenticationAlgorithms, authenticatorGetInfo, attestationRootCertificates
    } = statement, keypairCOSEAlgs = new Set();
    // 确保 attestation 陈述中的算法与元数据中指定的算法之一匹配
    authenticationAlgorithms.forEach(algSign => {
        // 将 algSign 字符串映射为 { kty,alg,crv }
        const algSignCOSEINFO = algSignToCOSEInfoMap[algSign];
        // 保留此语句以防 MDS 返回意外内容
        if (algSignCOSEINFO) keypairCOSEAlgs.add(algSignCOSEINFO);
    });

    // 提取用于比较的公钥 COSE 信息
    const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey),
        kty = decodedPublicKey.get(COSEKEYS.kty), alg = decodedPublicKey.get(COSEKEYS.alg);

    if (!kty) throw new Error('凭证公钥缺少 kty');
    if (!alg) throw new Error('凭证公钥缺少 alg');
    if (!kty) throw new Error('凭证公钥缺少 kty');

    // 假设所有值都是数字,因为这些值应该如此
    /** @type {{ kty: number, alg: number, crv?: number }} */
    const publicKeyCOSEInfo = { kty, alg };
    if (isCOSEPublicKeyEC2(decodedPublicKey)) {
        const crv = decodedPublicKey.get(COSEKEYS.crv);
        publicKeyCOSEInfo.crv = crv;
    }

    /**
     * 尝试将凭证公钥的算法与设备元数据中指定的算法之一进行匹配
     */
    let foundMatch = false;
    for (const keypairAlg of keypairCOSEAlgs) {
        // 确保算法和密钥类型匹配
        if (keypairAlg.alg === publicKeyCOSEInfo.alg && keypairAlg.kty === publicKeyCOSEInfo.kty) {
            // 对于椭圆曲线或 OKP 密钥,必须曲线编号一致,曲线不匹配时不设置 foundMatch(保持 false)
            const isEcOrOkp = (keypairAlg.kty === COSEKTY.EC2 || keypairAlg.kty === COSEKTY.OKP),
                curveMatches = isEcOrOkp ? (keypairAlg.crv === publicKeyCOSEInfo.crv) : true;
            if (curveMatches) foundMatch = true; // RSA 或其他类型的密钥,直接认为匹配
        }
        if (foundMatch) break;
    }

    // 确保公钥属于允许的算法之一
    if (!foundMatch) {
        /**
         * 根据 MDS 算法生成有用的错误输出
         * 示例:
         * @example
         * [
         *   'rsassa_pss_sha256_raw' (COSE 信息: { kty: 3, alg: -37 }),
         *   'secp256k1_ecdsa_sha256_raw' (COSE 信息: { kty: 2, alg: -47, crv: 8 })
         * ]
         */
        const debugMDSAlgs = authenticationAlgorithms.map(
            algSign => `'${algSign}' (COSE 信息: ${stringifyCOSEInfo(algSignToCOSEInfoMap[algSign])})`,
        ), strMDSAlgs = JSON.stringify(debugMDSAlgs, null, 2).replace(/"/g, ''),
            strPubKeyAlg = stringifyCOSEInfo(publicKeyCOSEInfo); // 构造关于公钥的错误输出

        throw new Error(`公钥参数 ${strPubKeyAlg} 与以下任何元数据算法均不匹配:\n${strMDSAlgs}`);
    }

    /**
     * 确认 attestation 陈述的算法是元数据支持的算法之一
     */
    if (attestationStatementAlg !== undefined && authenticatorGetInfo?.algorithms !== undefined) {
        const getInfoAlgs = authenticatorGetInfo.algorithms.map((_alg) => _alg.alg);
        if (getInfoAlgs.indexOf(attestationStatementAlg) < 0)
            throw new Error(`Attestation 陈述算法 ${attestationStatementAlg} 与 ${getInfoAlgs} 中的任何一个均不匹配`);
    }

    // 准备检查证书链
    const authenticatorCerts = x5c.map(convertCertBufferToPEM),
        statementRootCerts = attestationRootCertificates.map(convertCertBufferToPEM);

    /**
     * 如果身份验证器在其 x5c 中恰好返回一个证书,并且该证书在元数据陈述中,
     * 则该身份验证器是"自引用的";在这种情况下,我们跳过证书链验证;
     */
    let authenticatorIsSelfReferencing = false;
    if (authenticatorCerts.length === 1 && statementRootCerts.indexOf(authenticatorCerts[0]) >= 0)
        authenticatorIsSelfReferencing = true;
    if (!authenticatorIsSelfReferencing) {
        try {
            await validateCertificatePath(authenticatorCerts, statementRootCerts);
        } catch (err) {
            throw new Error(`无法使用任何元数据根证书验证证书链:${err.message}`);
        }
    }

    return true;
};

// ================================= JWT签名验证处理 =================================
/**
 * 针对 FIDO MDS JWT 的轻量级验证,支持 EC2 和 RSA 算法;
 * - 查看定义:@see {@link verifyJWT}
 * - 如果需要支持更多 JWS 算法,可参考以下列表:
 *
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
 *
 * (摘自 https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1)
 *
 * @param {string} jwt - 待验证的 JWT 字符串(三段式 base64url 编码)
 * @param {BufferSource} leafCert - 叶子证书(DER 格式),用于提取公钥进行签名验证
 * @returns {Promise<boolean>} 签名验证通过时返回 true,否则抛出错误
 */
const verifyJWT = (jwt, leafCert) => {
    const [header, payload, signature] = jwt.split('.'), certCOSE = convertX509PublicKeyToCOSE(leafCert),
        data = utf8Tobytes(`${header}.${payload}`), signatureBytes = toBuffer(signature);

    if (isCOSEPublicKeyEC2(certCOSE))
        return verifyEC2({ data, signature: signatureBytes, cosePublicKey: certCOSE, shaHashOverride: COSEALG.ES256 });
    else if (isCOSEPublicKeyRSA(certCOSE)) return verifyRSA({ data, signature: signatureBytes, cosePublicKey: certCOSE });

    const kty = certCOSE.get(COSEKEYS.kty);
    throw new Error(`此方法不支持使用 kty 为 ${kty} 的公钥进行 JWT 验证`);
};

// ================================= BLOB验证处理 =================================
/**
 * 对符合 [FIDO 元数据服务 (MDS)](https://fidoalliance.org/metadata/) 规范的 BLOB 进行真实性与完整性验证,
 * 并提取其中包含的 FIDO2 元数据声明,此方法将发起网络请求以执行 CRL 等检查;
 * - 查看定义:@see {@link verifyMDSBlob}
 *
 * @param {string} blob - 从 MDS 服务器下载的 JWT(例如 https://mds3.fidoalliance.org)
 * @returns {Promise<{statements: object[],parsedNextUpdate: Date,payload: object}>}
 *  返回一个对象,包含解析出的元数据声明列表、下次更新时间的 Date 对象以及原始载荷对象
 */
const verifyMDSBlob = async blob => {
    // 解析 JWT
    const parsedJWT = parseJWT(blob), header = parsedJWT[0], payload = parsedJWT[1],
        headerCertsPEM = header.x5c.map(convertCertBufferToPEM);

    try {
        // 验证证书链
        const rootCerts = SettingsService.getRootCertificates({ identifier: 'mds' });
        await validateCertificatePath(headerCertsPEM, rootCerts);
    } catch (error) {
        // 根据 FIDO MDS 文档:"如果证书链无法验证或链中任一证书被吊销,应忽略该文件"
        throw new Error('无法验证 BLOB 证书路径', { cause: error });
    }

    // 验证 BLOB 的 JWT 签名
    const leafCert = headerCertsPEM[0], verified = await verifyJWT(blob, convertPEMToBytes(leafCert));
    if (!verified) throw new Error('无法验证 BLOB 签名'); // 根据 FIDO MDS 文档:"如果签名无效,FIDO 服务器应忽略该文件"

    // 缓存 FIDO2 设备的声明
    const statements = [];
    for (const entry of payload.entries) {
        // 仅缓存包含 `aaguid` 的条目
        if (entry.aaguid && entry.metadataStatement) statements.push(entry.metadataStatement);
    }

    // 将 nextUpdate 属性转换为 Date 对象,以便确定重新下载的时间(月份需要从 0 开始索引)
    const [year, month, day] = payload.nextUpdate.split('-'),
        parsedNextUpdate = new Date(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10));

    return { statements, parsedNextUpdate, payload };
};


// ================================= MetadataService实现 =================================
/**
 * 一个 `CachedMDS` 实例,不会触发刷新关联条目 BLOB 的尝试
 * @type {{ url: string, no: number, nextUpdate: Date }}
 */
const NonRefreshingMDS = { url: '', no: 0, nextUpdate: new Date(0) },
    defaultURLMDS = 'https://mds.fidoalliance.org/',// v3
    /** @type {{ DISABLED: 0, REFRESHING: 1, READY: 2 }} */
    SERVICE_STATE = { DISABLED: 0, REFRESHING: 1, READY: 2 },
    log = getLogger('MetadataService');

/**
 * `MetadataService` 的一个实现,能够下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * - 查看定义:@see {@link BaseMetadataService}、
 * https://fidoalliance.org/metadata/
 */
class BaseMetadataService {
    /**
     * 初始化 BaseMetadataService 实例
     */
    constructor() {
        /**
         * MDS 服务器缓存映射,键为 URL,值为 CachedMDS 信息
         * @type {Record<string, { url: string, no: number, nextUpdate: Date }>}
         */
        Object.defineProperty(this, "mdsCache", {
            enumerable: true, configurable: true, writable: true, value: {}
        });
        /**
         * 元数据声明缓存映射,键为 AAGUID 字符串,值为包含条目和 URL 的对象
         * @type {Record<string, { entry: Object, url: string }>}
         */
        Object.defineProperty(this, "statementCache", {
            enumerable: true, configurable: true, writable: true, value: {}
        });
        /**
         * 服务当前状态
         * @type {0 | 1 | 2}
         */
        Object.defineProperty(this, "state", {
            enumerable: true, configurable: true, writable: true, value: SERVICE_STATE.DISABLED
        });
        /**
         * 验证模式:'strict' 或宽松模式(允许跳过未注册的 AAGUID)
         * @type {'strict' | 'permissive'}
         */
        Object.defineProperty(this, "verificationMode", {
            enumerable: true, configurable: true, writable: true, value: 'strict'
        });
    }

    /**
     * 初始化元数据服务
     * @param {Object} [opts] - 初始化选项
     * @param {string[]} [opts.mdsServers] - MDS 服务器 URL 列表,默认使用 FIDO 官方服务器
     * @param {Object[]} [opts.statements] - 预先提供的元数据声明列表
     * @param {'strict' | 'permissive'} [opts.verificationMode] - 验证模式
     * @returns {Promise<void>}
     */
    async initialize(opts = {}) {
        // 重置声明缓存
        this.statementCache = {};

        const { mdsServers = [defaultURLMDS], statements, verificationMode } = opts;
        this.setState(SERVICE_STATE.REFRESHING);

        /**
         * 如果提供了元数据声明,则首先将它们加载到缓存中;
         * 这些声明在检测到过期时不会被刷新;
         */
        if (statements?.length) {
            let statementsAdded = 0;
            statements.forEach((statement) => {
                // 仅缓存兼容 FIDO2 认证器的声明
                if (statement.aaguid) {
                    this.statementCache[statement.aaguid] = {
                        entry: { metadataStatement: statement, statusReports: [], timeOfLastStatusChange: '1970-01-01' },
                        url: NonRefreshingMDS.url,
                    };
                    statementsAdded += 1;
                }
            });
            log(`已缓存 ${statementsAdded} 条本地声明`);
        }

        /**
         * 如果提供了 MDS 服务器,则从中下载 BLOB、验证它们,并将其条目添加到缓存中;
         * 通过这种方式加载的 BLOB 在检测到其中的条目过期时会被刷新;
         */
        if (mdsServers?.length) {
            // 获取当前缓存数量,以便知道从 MDS 服务器新增了多少声明
            const currentCacheCount = Object.keys(this.statementCache).length;
            let numServers = mdsServers.length;

            for (const url of mdsServers) {
                try {
                    const cachedMDS = { url, no: 0, nextUpdate: new Date(0) }, blob = await this.downloadBlob(cachedMDS);
                    await this.verifyBlob(blob, cachedMDS);
                } catch (err) {
                    log(`无法从 ${url} 下载 BLOB:`, err), numServers -= 1; // 通知错误并继续
                }
            }

            // 计算差值,得到成功新增的声明总数
            const newCacheCount = Object.keys(this.statementCache).length, cacheDiff = newCacheCount - currentCacheCount;
            log(`已从 ${numServers} 个元数据服务器缓存 ${cacheDiff} 条声明`);
        }

        if (verificationMode) this.verificationMode = verificationMode;
        this.setState(SERVICE_STATE.READY);
    }

    /**
     * 获取指定 AAGUID 的元数据声明
     * @param {string | Uint8Array} aaguid - 认证器 GUID(字符串或二进制形式)
     * @returns {Promise<Object | undefined>} 元数据声明对象,若未找到且模式非 strict 则返回 undefined
     * @throws {Error} 当 strict 模式下未找到声明或检测到认证器泄露时抛出错误
     */
    async getStatement(aaguid) {
        if (this.state === SERVICE_STATE.DISABLED || !aaguid) return;
        if (aaguid instanceof Uint8Array) aaguid = convertAAGUIDToString(aaguid);

        await this.pauseUntilReady(); // 如果缓存刷新正在进行,则等待服务就绪
        // 尝试获取缓存的声明
        const cachedStatement = this.statementCache[aaguid];
        if (!cachedStatement) {
            // FIDO 一致性要求 RP 仅支持已注册的 AAGUID
            if (this.verificationMode === 'strict') throw new Error(`未找到 aaguid"${aaguid}"的元数据声明`);
            return; // 允许在不使用元数据的情况下继续注册验证
        }

        // 如果声明指向 MDS API,则检查 MDS 的 nextUpdate 是否需要刷新
        if (cachedStatement.url) {
            const mds = this.mdsCache[cachedStatement.url], now = new Date();
            if (now > mds.nextUpdate) {
                try {
                    this.setState(SERVICE_STATE.REFRESHING);
                    const blob = await this.downloadBlob(mds);
                    await this.verifyBlob(blob, mds);
                }
                finally { this.setState(SERVICE_STATE.READY) }
            }
        }

        const { entry } = cachedStatement;
        // 检查该 aaguid 的状态报告中是否存在"已泄露"状态
        for (const report of entry.statusReports) {
            const { status } = report;
            if (
                status === 'USER_VERIFICATION_BYPASS' || status === 'ATTESTATION_KEY_COMPROMISE' ||
                status === 'USER_KEY_REMOTE_COMPROMISE' || status === 'USER_KEY_PHYSICAL_COMPROMISE'
            ) throw new Error(`检测到 aaguid"${aaguid}"已泄露`);
        }

        return entry.metadataStatement;
    }

    /**
     * 从 MDS 下载并处理最新的 BLOB
     * @param {{ url: string, no: number, nextUpdate: Date }} cachedMDS - 缓存的 MDS 信息
     * @returns {Promise<string>} BLOB 原始文本内容
     */
    async downloadBlob(cachedMDS) {
        // 获取最新的"BLOB"(FIDO 的术语)
        const { url } = cachedMDS, resp = await fetch(url), data = await resp.text();
        return data;
    }

    /**
     * 验证并处理 MDS 元数据 BLOB
     * @param {string} blob - BLOB 原始文本内容
     * @param {{ url: string, no: number, nextUpdate: Date }} cachedMDS - 缓存的 MDS 信息
     * @returns {Promise<void>}
     */
    async verifyBlob(blob, cachedMDS) {
        const { url, no } = cachedMDS, { payload, parsedNextUpdate } = await verifyMDSBlob(blob);

        // 来自 FIDO MDS 文档:"如果文件的编号(no)小于或等于本地缓存的最后一个 BLOB 的编号,则忽略该文件;"
        if (payload.no <= no) throw new Error(`最新 BLOB 编号 ${payload.no} 不大于先前编号 ${no}`);

        // 缓存 FIDO2 设备的声明
        for (const entry of payload.entries) {
            // 仅缓存包含 `aaguid` 的条目
            if (entry.aaguid) this.statementCache[entry.aaguid] = { entry, url };
        }

        if (url) {
            // 记录服务器信息以便后续刷新
            this.mdsCache[url] = {
                ...cachedMDS,
                // 存储 payload 中的 `no`,确保获取序列中的下一个 BLOB
                no: payload.no, nextUpdate: parsedNextUpdate // 记录需要刷新此 BLOB 的时间
            };
        } else {
            /**
             * 该 BLOB 不会被刷新,但如果其 `nextUpdate` 早于当前时间,仍应发出警告
             */
            if (parsedNextUpdate < new Date())
                // TODO(2026年2月):此处抛出一个具体的错误会更便于开发者处理,
                // 然后在更上层记录该消息,同时包含过期 BLOB 在数组中的索引;
                log(`⚠️ 此 MDS BLOB(序列号:${payload.no})的数据自 ${parsedNextUpdate.toISOString()} 起已过期;
                请考虑使用更新的 MDS BLOB 重新初始化 MetadataService;`);
        }
    }

    /**
     * 辅助方法:暂停执行直到服务就绪
     * @returns {Promise<void>}
     */
    pauseUntilReady() {
        if (this.state === SERVICE_STATE.READY) return new Promise((resolve) => resolve());

        // 状态未就绪,设置轮询
        const readyPromise = new Promise((resolve, reject) => {
            const totalTimeoutMS = 70000, intervalMS = 100;
            let iterations = totalTimeoutMS / intervalMS;

            // 每隔 `intervalMS` 毫秒检查一次服务状态
            const intervalID = globalThis.setInterval(() => {
                if (iterations < 1) clearInterval(intervalID),
                    reject(`状态在 ${totalTimeoutMS / 1000} 秒内未能变为 READY`);
                else if (this.state === SERVICE_STATE.READY) clearInterval(intervalID), resolve();
                iterations -= 1;
            }, intervalMS);
        });

        return readyPromise;
    }

    /**
     * 报告服务状态变更
     * @param {0 | 1 | 2} newState - 新状态值
     * @returns {void}
     */
    setState(newState) {
        this.state = newState;
        if (newState === SERVICE_STATE.DISABLED) log('MetadataService 已禁用');
        else if (newState === SERVICE_STATE.REFRESHING) log('MetadataService 正在刷新');
        else if (newState === SERVICE_STATE.READY) log('MetadataService 已就绪');
    }
}

/**
 * 用于协调与 FIDO 元数据交互的基础服务;
 * 包括 BLOB 下载与解析,以及按需请求和缓存各个元数据声明;
 * - 查看定义:@see {@link MetadataService}、
 * https://fidoalliance.org/metadata/
 * @type {BaseMetadataService}
 */
const MetadataService = new BaseMetadataService();

export {
    AlgSign, parseJWT, verifyAttestationWithMetadata, algSignToCOSEInfoMap, verifyJWT, verifyMDSBlob,
    BaseMetadataService, MetadataService
};