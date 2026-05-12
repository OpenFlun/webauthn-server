# @flun/webauthn-server <!-- omit in toc -->

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@flun/webauthn-server?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@flun/webauthn-server)

**@flun/webauthn-server** 是一个专为 Node.js 环境设计的 WebAuthn（含 Passkeys）服务端工具库，采用 TypeScript 编写，提供对证书、密钥及 CBOR 编码的完整处理能力。它简化了 FIDO2/Passkey 身份验证后端的构建过程，支持当前所有主流的 WebAuthn 认证格式。

> **模块规范**：本包使用 ESM 模块编写。要求 Node.js ≥ 22.12.0，若使用低版本 Node 则需通过 `import` 语法导入（不建议在低于 22.12.0 的环境中使用 `require()`）。

## 目录

- [目录](#目录)
- [安装](#安装)
  - [Node.js 22.12.0 及以上版本](#nodejs-22120-及以上版本)
- [主要功能](#主要功能)
- [快速开始](#快速开始)
  - [后端集成示例](#后端集成示例)
  - [前端配合说明](#前端配合说明)
- [API 参考](#api-参考)
  - [注册相关](#注册相关)
  - [认证相关](#认证相关)
  - [元数据与设置服务](#元数据与设置服务)
  - [辅助工具函数（`helpers` 模块）](#辅助工具函数helpers-模块)
    - [编解码与转换](#编解码与转换)
    - [COSE 公钥处理](#cose-公钥处理)
    - [证书处理](#证书处理)
    - [认证器数据解析](#认证器数据解析)
    - [签名验证与哈希](#签名验证与哈希)
    - [通用工具](#通用工具)
- [支持的认证格式](#支持的认证格式)
- [错误处理](#错误处理)
- [许可证](#许可证)
- [相关链接](#相关链接)

---

## 安装

### Node.js 22.12.0 及以上版本

```sh
npm install @flun/webauthn-server
```

> **注意**：本库依赖 Node.js 内置的 `crypto`、`fetch` 等模块，请确保运行环境为 Node.js ≥ 22.12.0。

---

## 主要功能

- ✅ **WebAuthn 注册与认证**
  提供 `generateRegistrationOptions` / `verifyRegistrationResponse` 和 `generateAuthenticationOptions` / `verifyAuthenticationResponse` 两对核心方法，完整实现 WebAuthn 后端逻辑。

- ✅ **全格式证明支持**
  支持 `packed`、`fido-u2f`、`android-safetynet`、`android-key`、`tpm`、`apple`、`none` 等所有标准认证格式。

- ✅ **元数据服务 (MDS)**
  内置 `MetadataService` 可下载并解析 FIDO 联盟的元数据 BLOB，验证认证器真伪与状态。

- ✅ **证书链验证**
  提供证书路径验证、吊销检查、X.509 解析等工具。

- ✅ **丰富的辅助工具**
  通过 `@flun/webauthn-server/helpers` 子路径导出大量底层工具：Base64URL 编解码、COSE ↔ PKCS 转换、authData 解析、签名验证等。

---

## 快速开始

### 后端集成示例

以下是一个基于 Express 的完整后端示例，展示了用户注册与登录的 WebAuthn 流程。

```js
import express from 'express';
import {
  generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse
} from '@flun/webauthn-server';

const app = express();
app.use(express.json());

// 模拟用户数据库
const users = {
  'user@example.com': {
    id: Buffer.from('user-id-buffer'),
    credentials: []
  }
};

// 临时挑战存储（生产环境建议使用 session 或 redis）
const challengeStore = new Map();

// 1. 注册 - 生成选项
app.post('/api/register/begin', async (req, res) => {
  const { username } = req.body;
  const user = users[username];
  if (!user) return res.status(404).json({ error: 'User not found' });

  const options = await generateRegistrationOptions({
    rpName: 'My App',
    rpID: 'localhost',
    userName: username,
    userID: user.id,
    attestationType: 'none',
  });

  challengeStore.set(username + '_reg', options.challenge);
  res.json(options);
});

// 2. 注册 - 验证响应
app.post('/api/register/complete', async (req, res) => {
  const { username, response } = req.body;
  const expectedChallenge = challengeStore.get(username + '_reg');

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: 'http://localhost:3000',
    expectedRPID: 'localhost',
    requireUserVerification: true,
  });

  if (verification.verified) {
    const { credential } = verification.registrationInfo;
    users[username].credentials.push({
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports
    });
    challengeStore.delete(username + '_reg');
    res.json({ verified: true });
  } else {
    res.status(400).json({ verified: false });
  }
});

// 3. 认证 - 生成选项
app.post('/api/login/begin', async (req, res) => {
  const { username } = req.body;
  const user = users[username];
  if (!user) return res.status(404).json({ error: 'User not found' });

  const options = await generateAuthenticationOptions({
    rpID: 'localhost',
    allowCredentials: user.credentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
  });

  challengeStore.set(username + '_auth', options.challenge);
  res.json(options);
});

// 4. 认证 - 验证响应
app.post('/api/login/complete', async (req, res) => {
  const { username, response } = req.body;
  const expectedChallenge = challengeStore.get(username + '_auth');
  const user = users[username];
  const credential = user.credentials.find(c => c.id === response.id);

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: 'http://localhost:7296',
    expectedRPID: 'localhost',
    credential,
  });

  if (verification.verified) {
    credential.counter = verification.authenticationInfo.newCounter;
    challengeStore.delete(username + '_auth');
    res.json({ verified: true });
  } else {
    res.status(400).json({ verified: false });
  }
});

app.listen(3001, () => console.log('Backend running on port 3001'));
```

### 前端配合说明

前端需使用配套的浏览器库 `@flun/webauthn-browser`，可通过 CDN 或 npm 引入。

```html
<script src="https://unpkg.com/@flun/webauthn-browser/dist/index.js"></script>
```

调用示例：

```js
// 注册
const regOptions = await fetch('/api/register/begin', ...).then(r => r.json());
const regResponse = await flunWebAuthnBrowser.startRegistration({ optionsJSON: regOptions });
await fetch('/api/register/complete', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, response: regResponse })
});

// 登录
const authOptions = await fetch('/api/login/begin', ...).then(r => r.json());
const authResponse = await flunWebAuthnBrowser.startAuthentication({ optionsJSON: authOptions });
await fetch('/api/login/complete', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, response: authResponse })
});
```

---

## API 参考

### 注册相关

| 方法                                   | 描述                                                 |
| -------------------------------------- | ---------------------------------------------------- |
| `generateRegistrationOptions(options)` | 生成用于 `navigator.credentials.create()` 的选项参数 |
| `verifyRegistrationResponse(options)`  | 验证客户端返回的注册响应，返回验证结果及凭证信息     |

### 认证相关

| 方法                                     | 描述                                                 |
| ---------------------------------------- | ---------------------------------------------------- |
| `generateAuthenticationOptions(options)` | 生成用于 `navigator.credentials.get()` 的选项参数    |
| `verifyAuthenticationResponse(options)`  | 验证客户端返回的认证响应，返回验证结果及更新的计数器 |

### 元数据与设置服务

| 导出项                              | 描述                                                               |
| ----------------------------------- | ------------------------------------------------------------------ |
| `MetadataService`                   | 协调 FIDO 元数据交互的基础服务实例（`BaseMetadataService` 的实例） |
| `SettingsService`                   | 管理各类 attestation 声明格式根证书的服务实例                      |
| `supportedCOSEAlgorithmIdentifiers` | 支持的加密算法标识符数组                                           |
| `AlgSign`                           | 支持的签名算法数组                                                 |

### 辅助工具函数（`helpers` 模块）

可通过 `@flun/webauthn-server/helpers` 导入所有底层工具。

#### 编解码与转换

| 函数                  | 描述                                   |
| --------------------- | -------------------------------------- |
| `fromBuffer(buffer)`  | 将 ArrayBuffer 编码为 Base64URL 字符串 |
| `toBuffer(base64url)` | 将 Base64URL 字符串解码为 ArrayBuffer  |
| `utf8Tob64url(str)`   | UTF-8 字符串 → Base64URL               |
| `b64urlToUtf8(str)`   | Base64URL → UTF-8 字符串               |
| `toBase64(base64url)` | Base64URL → 标准 Base64                |
| `isBase64(str)`       | 检查是否为 Base64 编码                 |
| `isBase64URL(str)`    | 检查是否为 Base64URL 编码              |
| `trimPadding(str)`    | 移除 Base64URL 填充字符                |
| `fromHex(hex)`        | 十六进制字符串 → Uint8Array            |
| `toHex(buf)`          | Uint8Array → 十六进制字符串            |
| `utf8Tobytes(str)`    | UTF-8 → Uint8Array                     |
| `bytesToUtf8(buf)`    | Uint8Array → UTF-8                     |
| `asciiToBytes(str)`   | ASCII → Uint8Array                     |
| `areEqual(a, b)`      | 比较两个 Uint8Array 是否相等           |
| `concat(...arrays)`   | 拼接多个 Uint8Array                    |
| `toDataView(buf)`     | 转换为 DataView 对象                   |

#### COSE 公钥处理

| 类型/函数                                                                   | 描述                                    |
| --------------------------------------------------------------------------- | --------------------------------------- |
| `COSEKEYS`, `COSEKTY`, `COSECRV`, `COSEALG`                                 | COSE 标准键值枚举                       |
| `COSEPublicKey`, `COSEPublicKeyOKP`, `COSEPublicKeyEC2`, `COSEPublicKeyRSA` | COSE 公钥类型                           |
| `isCOSEPublicKeyOKP()`, `isCOSEPublicKeyEC2()`, `isCOSEPublicKeyRSA()`      | 类型守卫                                |
| `isCOSEKty()`, `isCOSECrv()`, `isCOSEAlg()`                                 | COSE 参数值检查                         |
| `decodeCredentialPublicKey(buf)`                                            | 解码 CBOR 编码的凭证公钥为 Map 对象     |
| `convertCOSEtoPKCS(coseKey)`                                                | 将 COSE 公钥转换为 PKCS 格式            |
| `convertX509PublicKeyToCOSE(certDer)`                                       | 从 X.509 证书提取公钥并转换为 COSE 结构 |

#### 证书处理

| 函数/类                                    | 描述                                      |
| ------------------------------------------ | ----------------------------------------- |
| `convertCertBufferToPEM(buf)`              | 将证书缓冲区转换为 PEM 字符串             |
| `convertPEMToBytes(pem)`                   | 将 PEM 证书转换为字节数组                 |
| `getCertificateInfo(pem)`                  | 提取 PEM 证书的颁发者、主题、有效期等信息 |
| `isCertRevoked(certPem)`                   | 检查证书是否被其 CRL 吊销                 |
| `validateCertificatePath(certs)`           | 验证证书链的有效性                        |
| `validateExtFIDOGenCEAAGUID(cert, aaguid)` | 校验证书中的 FIDO Gen CE AAGUID 扩展      |
| `InvalidSubjectAndIssuer`                  | 证书链验证失败时抛出的错误类              |

#### 认证器数据解析

| 函数/类型                            | 描述                          |
| ------------------------------------ | ----------------------------- |
| `decodeAttestationObject(buf)`       | 解析 attestationObject 缓冲区 |
| `decodeClientDataJSON(base64url)`    | 解析 clientDataJSON           |
| `parseAuthenticatorData(authData)`   | 解析 authData，返回可读结构   |
| `parseBackupFlags(flags)`            | 解析备份状态标志 (BE/BS)      |
| `decodeAuthenticatorExtensions(buf)` | 解码扩展数据                  |
| `InvalidBackupFlags`                 | 备份标志无效时抛出的错误类    |

#### 签名验证与哈希

| 函数                                              | 描述                              |
| ------------------------------------------------- | --------------------------------- |
| `verifySignature({ signature, data, publicKey })` | 通用签名验证入口                  |
| `verifyEC2()`, `verifyOKP()`, `verifyRSA()`       | 特定算法签名验证                  |
| `toHash(data, algorithm?)`                        | 计算哈希摘要（默认 SHA-256）      |
| `mapX509SignatureAlgToCOSEAlg(oid)`               | X.509 签名算法 OID → COSE 算法 ID |

#### 通用工具

| 函数/类                                      | 描述                               |
| -------------------------------------------- | ---------------------------------- |
| `generateChallenge()`                        | 生成随机挑战值                     |
| `generateUserID()`                           | 生成随机用户 ID                    |
| `matchExpectedRPID(rpIdHash, expectedRPIDs)` | 匹配 RP ID 哈希值                  |
| `UnexpectedRPIDHash`                         | RP ID 不匹配时抛出的错误类         |
| `fetch(url, options?)`                       | 跨运行时的 fetch 封装              |
| `getLogger(name?)`                           | 获取基于 debug 的日志记录器        |
| `convertAAGUIDToString(aaguid)`              | 将 AAGUID 缓冲区转换为 UUID 字符串 |
| `digest(algorithm, data)`                    | 生成数据摘要                       |
| `getRandomValues(arr)`                       | 填充随机字节                       |
| `verify(algorithm, key, signature, data)`    | 底层验签函数                       |

---

## 支持的认证格式

本库完全兼容 [W3C WebAuthn 规范](https://w3c.github.io/webauthn/#sctn-defined-attestation-formats) 中定义的所有证明格式：

- **Packed**
- **FIDO U2F**
- **Android SafetyNet**
- **Android Key**
- **TPM**
- **Apple**
- **None**

每种格式的验证逻辑均已内置，无需额外配置。

---

## 错误处理

库中大部分验证方法会在失败时抛出明确的错误类，例如：

- `UnexpectedRPIDHash`：RP ID 哈希不匹配
- `InvalidSubjectAndIssuer`：证书链无效
- `InvalidBackupFlags`：备份标志组合非法

建议使用 `try...catch` 捕获这些错误并作出相应处理。

---

## 许可证

ISC © [flun](https://github.com/OpenFlun)

---

## 相关链接

- [GitHub 仓库](https://github.com/OpenFlun/webauthn-server)
- [前端浏览器库 @flun/webauthn-browser](https://www.npmjs.com/package/@flun/webauthn-browser)