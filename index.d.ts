/**
 * WebAuthn认证模块 主要功能:
 * ```js
 * generateAuthenticationOptions();                // 生成用于身份验证器认证的参数
 * verifyAuthenticationResponse();                 // 验证用户是否合法完成了认证流程
 * generateRegistrationOptions();                  // 生成用于身份验证器注册的参数
 * verifyRegistrationResponse();                   // 验证用户是否合法完成了注册流程
 * class BaseMetadataService{};                    // 下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * const MetadataService= new BaseMetadataService; // 用于协调与 FIDO 元数据交互的基础服务;
 * class BaseSettingsService{};                    // 用于管理各类 attestation 语句格式的根证书;
 * const SettingsService= new BaseSettingsService; // 用于为所有支持的证明声明格式指定可接受的根证书;
 * const supportedCOSEAlgorithmIdentifiers=[];     // 支持的加密算法标识符
 * const AlgSign=[];                               // 支持的签名算法数组
 * ```
 * ---
 *
 * **完整前后端集成示例(开箱即用)**
 *
 * 以下示例包含前端 HTML/JS 代码和后端 Node.js (Express) 代码,使用 `@flun/webauthn-browser` 简化前端调用;
 *
 * ### 后端代码(Node.js + Express)
 * ```js
 * import express from 'express';
 * import {
 *   generateRegistrationOptions, verifyRegistrationResponse,
 *   generateAuthenticationOptions, verifyAuthenticationResponse
 * } from '@flun/webauthn-server';
 *
 * const app = express();
 * app.use(express.json());
 *
 * // 模拟用户数据库
 * const users = {
 *   'user@example.com': {
 *     id: Buffer.from('user-id-buffer'), // 用户唯一标识(Buffer 或 Uint8Array)
 *     credentials: []
 *   }
 * };
 *
 * // 临时存储挑战值(生产环境建议使用 session 或 redis)
 * const challengeStore = new Map();
 *
 * // 1. 注册:生成选项
 * app.post('/api/register/begin', async (req, res) => {
 *   const { username } = req.body;
 *   const user = users[username];
 *   if (!user) return res.status(404).json({ error: 'User not found' });
 *
 *   const options = await generateRegistrationOptions({
 *     rpName: 'My App',
 *     rpID: 'localhost',               // 实际部署时改为真实域名
 *     userName: username,
 *     userID: user.id,
 *     attestationType: 'none',
 *   });
 *
 *   // 保存挑战值用于后续验证
 *   challengeStore.set(username + '_reg', options.challenge);
 *   res.json(options);
 * });
 *
 * // 2. 注册:验证响应
 * app.post('/api/register/complete', async (req, res) => {
 *   const { username, response } = req.body;
 *   const expectedChallenge = challengeStore.get(username + '_reg');
 *
 *   const verification = await verifyRegistrationResponse({
 *     response,
 *     expectedChallenge,
 *     expectedOrigin: 'http://localhost:3000',  // 前端页面地址
 *     expectedRPID: 'localhost',
 *     requireUserVerification: true,
 *   });
 *
 *   if (verification.verified) {
 *     const { credential } = verification.registrationInfo;
 *     users[username].credentials.push({
 *       id: credential.id,
 *       publicKey: credential.publicKey,
 *       counter: credential.counter,
 *       transports: credential.transports
 *     });
 *     challengeStore.delete(username + '_reg');
 *     res.json({ verified: true });
 *   } else {
 *     res.status(400).json({ verified: false });
 *   }
 * });
 *
 * // 3. 认证:生成选项
 * app.post('/api/login/begin', async (req, res) => {
 *   const { username } = req.body;
 *   const user = users[username];
 *   if (!user) return res.status(404).json({ error: 'User not found' });
 *
 *   const options = await generateAuthenticationOptions({
 *     rpID: 'localhost',
 *     allowCredentials: user.credentials.map(cred => ({
 *       id: cred.id,
 *       type: 'public-key',
 *       transports: cred.transports,
 *     })),
 *   });
 *
 *   challengeStore.set(username + '_auth', options.challenge);
 *   res.json(options);
 * });
 *
 * // 4. 认证:验证响应
 * app.post('/api/login/complete', async (req, res) => {
 *   const { username, response } = req.body;
 *   const expectedChallenge = challengeStore.get(username + '_auth');
 *   const user = users[username];
 *   const credential = user.credentials.find(c => c.id === response.id);
 *
 *   const verification = await verifyAuthenticationResponse({
 *     response,
 *     expectedChallenge,
 *     expectedOrigin: 'http://localhost:3000',
 *     expectedRPID: 'localhost',
 *     credential,
 *   });
 *
 *   if (verification.verified) {
 *     // 更新计数器
 *     credential.counter = verification.authenticationInfo.newCounter;
 *     challengeStore.delete(username + '_auth');
 *     res.json({ verified: true });
 *   } else {
 *     res.status(400).json({ verified: false });
 *   }
 * });
 *
 * app.listen(3001, () => console.log('Backend running on port 3001'));
 * ```
 *
 * ### 前端代码(HTML + JavaScript)
 * 在 HTML 中引入 `@flun/webauthn-browser` 库,使用全局对象 `flunWebAuthnBrowser` 提供的
 * `startRegistration` 和 `startAuthentication` 方法;
 *
 * ```html
 * <!DOCTYPE html>
 * <html>
 * <head>
 *   <title>WebAuthn Demo</title>
 *   <script src="https://unpkg.com/@flun/webauthn-browser/dist/index.js"></script>
 * </head>
 * <body>
 *   <h2>注册</h2>
 *   <input type="text" id="regUsername" placeholder="用户名" value="user@example.com">
 *   <button id="registerBtn">注册安全密钥</button>
 *
 *   <h2>登录</h2>
 *   <input type="text" id="loginUsername" placeholder="用户名" value="user@example.com">
 *   <button id="loginBtn">使用安全密钥登录</button>
 *
 *   <script>
 *     // 后端 API 地址
 *     const API_BASE = 'http://localhost:3001';
 *
 *     // 注册流程
 *     document.getElementById('registerBtn').onclick = async () => {
 *       const username = document.getElementById('regUsername').value;
 *
 *       // 1. 从后端获取注册选项
 *       const regOptionsRes = await fetch(`${API_BASE}/api/register/begin`, {
 *         method: 'POST',
 *         headers: { 'Content-Type': 'application/json' },
 *         body: JSON.stringify({ username })
 *       });
 *       const options = await regOptionsRes.json();
 *
 *       // 2. 调用浏览器 WebAuthn API(由 @flun/webauthn-browser 封装)
 *       //    注意:必须使用 { optionsJSON: options } 格式
 *       const response = await flunWebAuthnBrowser.startRegistration({ optionsJSON: options });
 *
 *       // 3. 将响应发送到后端验证
 *       const verifyRes = await fetch(`${API_BASE}/api/register/complete`, {
 *         method: 'POST',
 *         headers: { 'Content-Type': 'application/json' },
 *         body: JSON.stringify({ username, response })
 *       });
 *       const result = await verifyRes.json();
 *       if (result.verified) {
 *         alert('注册成功!');
 *       } else {
 *         alert('注册验证失败');
 *       }
 *     };
 *
 *     // 登录流程
 *     document.getElementById('loginBtn').onclick = async () => {
 *       const username = document.getElementById('loginUsername').value;
 *
 *       // 1. 获取认证选项
 *       const authOptionsRes = await fetch(`${API_BASE}/api/login/begin`, {
 *         method: 'POST',
 *         headers: { 'Content-Type': 'application/json' },
 *         body: JSON.stringify({ username })
 *       });
 *       const options = await authOptionsRes.json();
 *
 *       // 2. 调用浏览器 WebAuthn API 进行认证
 *       const response = await flunWebAuthnBrowser.startAuthentication({ optionsJSON: options });
 *
 *       // 3. 后端验证
 *       const verifyRes = await fetch(`${API_BASE}/api/login/complete`, {
 *         method: 'POST',
 *         headers: { 'Content-Type': 'application/json' },
 *         body: JSON.stringify({ username, response })
 *       });
 *       const result = await verifyRes.json();
 *       if (result.verified) {
 *         alert('登录成功!');
 *       } else {
 *         alert('登录失败');
 *       }
 *     };
 *   </script>
 * </body>
 * </html>
 * ```
 *
 * **关键说明**
 * - 前端通过 `<script src="https://unpkg.com/@flun/webauthn-browser/dist/index.js"></script>` 引入,
 *   全局对象为 `flunWebAuthnBrowser`;
 * - 调用 `startRegistration` 和 `startAuthentication` 时,必须传入 `{ optionsJSON: options }` 格式的参数对象;
 * - 后端生成的 `options` 对象(来自 `generateRegistrationOptions` 或 `generateAuthenticationOptions`)
 *   直接作为 `optionsJSON` 的值;
 * - 生产环境中请使用 HTTPS(WebAuthn 要求安全上下文),并妥善存储挑战值和用户凭证;
 *
 * **前端工具函数**
 *
 * `flunWebAuthnBrowser` 全局对象还提供了以下辅助函数,可用于特性检测、手动取消流程、编解码等操作:
 *
 * `startAuthentication` 支持 `{ optionsJSON, useBrowserAutofill?, verifyBrowserAutofillInput? }` 参数;
 * `browserSupportsWebAuthnAutofill` 依赖 `PublicKeyCredential.isConditionalMediationAvailable`;
 * ```js
 * browserSupportsWebAuthn();             // 检测当前浏览器是否支持 WebAuthn
 * browserSupportsWebAuthnAutofill();     // 检测浏览器是否支持 WebAuthn 条件式自动填充
 * platformAuthenticatorIsAvailable();    // 检测平台身份验证器(如 Windows Hello、指纹传感器)是否可用
 * startRegistration(options);            // 发起注册流程,参数 `{ optionsJSON, useAutoRegister? }`
 * startAuthentication(options);          // 发起认证流程
 * WebAuthnAbortService.cancelCeremony(); // 手动取消正在进行的注册/认证流程
 * class WebAuthnError{};                 // 自定义错误类,包含 `code` 属性,用于区分不同类型的 WebAuthn 错误
 * base64URLStringToBuffer(base64url);    // 将 Base64URL 字符串转换为 `ArrayBuffer`
 * bufferToBase64URLString(buffer);       // 将 `ArrayBuffer` 转换为 Base64URL 字符串
 * ```
 * 使用示例:
 * ```js
 * // 检测支持性
 * if (flunWebAuthnBrowser.browserSupportsWebAuthn()) {
 *   // 可以使用 WebAuthn
 * }
 *
 * // 取消流程(例如用户点击"取消"按钮)
 * flunWebAuthnBrowser.WebAuthnAbortService.cancelCeremony();
 *
 * // 捕获错误
 * try {
 *   await flunWebAuthnBrowser.startRegistration({ optionsJSON });
 * } catch (err) {
 *   if (err.code === 'ERROR_CEREMONY_ABORTED') {
 *     console.log('用户取消了操作');
 *   }
 * }
 * ```
 *
 * 以上示例完整覆盖了注册和认证流程,用户只需复制代码、修改 `rpID` 和 `origin` 为实际域名即可运行;
 *
 * ---
 */
declare module './index.js' { }
export * from './authentication/index.js';
export { AlgSign, BaseMetadataService, MetadataService, BaseSettingsService, SettingsService } from './metadata/index.js';
export * from './registration/index.js';