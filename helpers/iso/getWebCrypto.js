let webCrypto = undefined;
/**
 * 内部使用的辅助对象,主要用于测试时模拟和重置缓存;
 * - 查看定义:{@link _getWebCryptoInternals}
 *
 * @type {{
 *   stubThisGlobalThisCrypto: () => Crypto | undefined;
 *   setCachedCrypto: (newCrypto: Crypto | undefined) => void;
 * }}
 */
const _getWebCryptoInternals = {
    stubThisGlobalThisCrypto: () => globalThis.crypto,
    setCachedCrypto: newCrypto => webCrypto = newCrypto // 便于重置文件顶部的 `webCrypto` 变量
};

/**
 * 当无法在当前运行时环境中定位到 Crypto API 实例时抛出的错误;
 * - 查看定义:@see {@link MissingWebCrypto}
 * @extends Error
 */
class MissingWebCrypto extends Error {
    constructor() {
        const message = '无法定位 Crypto API 的实例';
        super(message), this.name = 'MissingWebCrypto';
    }
}

/**
 * 尝试从当前运行环境获取 Crypto API 的实例,支持 Node.js(v20+)以及实现了 Web API 的其他环境(如 Deno、Bun);
 * - 查看定义:@see {@link getWebCrypto}
 * @returns {Promise<Crypto>} 解析为 Crypto 对象(可通过 `.subtle` 访问 SubtleCrypto 接口);
 * @throws {MissingWebCrypto} 当无法定位 Crypto API 时,Promise 将被拒绝并携带该错误;
 */
const getWebCrypto = () => {
    /**
     * 你好!如果你来到这里想知道为什么这个方法是异步的,而 `globalThis.crypto` 的访问却是同步的,
     * 这是为了尽量减少与此方法同步化相关的大量重构工作;例如,如果我们将此方法同步化,
     * `generateRegistrationOptions()` 和 `generateAuthenticationOptions()` 也会变成同步的
     * (因为这两个方法中没有其他异步操作),这将是本库核心 API 的一个破坏性变更;
     *
     * TODO:如果你在 2025 年 2 月之后读到这段注释,请考虑是否还有必要保持此方法为异步;
     */
    const toResolve = new Promise((resolve, reject) => {
        if (webCrypto) return resolve(webCrypto);

        const _globalThisCrypto = _getWebCryptoInternals.stubThisGlobalThisCrypto();
        if (_globalThisCrypto) return webCrypto = _globalThisCrypto, resolve(webCrypto);

        return reject(new MissingWebCrypto());
    });
    return toResolve;
};

export { _getWebCryptoInternals, MissingWebCrypto, getWebCrypto };