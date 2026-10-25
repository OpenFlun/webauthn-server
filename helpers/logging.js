/**
 * 生成一个 `debug` 日志记录器实例,该实例基于 "flunWebauthn" 扩展,以保证命名的一致性;
 *
 * 有关如何在使用 @flun/webauthn-server 时控制日志输出的信息,请参阅 https://www.npmjs.com/package/debug
 * - 查看定义:@see {@link getLogger}
 * @param {string} _name - 日志记录器的命名空间(例如 'mds')
 * @returns {(message: string, ...rest: unknown[]) => void} 一个接受消息和可选参数的空操作日志函数
 * - 示例:
 * @example
 * const log = getLogger('mds');
 * log('hello'); // flunWebauthn:mds hello +0ms
 */
const getLogger = _name => {
    // 目前这是一个空操作,我正在寻找更好的 debug 日志记录技术
    return (_message, ..._rest) => { };
};

export { getLogger };