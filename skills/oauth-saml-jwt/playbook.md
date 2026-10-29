# OAuth / SAML / JWT 判断流程

## JWT

> 视角：黑盒。**判断流程优先，先解码看 alg/kid 再决定，不背 payload。**

### 排他声明

仅当目标是 `eyJ` 三段 token 时用本 skill（本类唯一强信号）。

- SQL 注入绕登录 → sqli
- OAuth 流程问题（redirect_uri/state）→ oauth-redirect.md

### 一句话说清

JWT = header.payload.signature，安全性全在"服务端怎么选算法和密钥"。

### 判断流程（★ 核心，先解码再决定）

#### Step 0 — 解码看 alg / kid
1 个动作（无需请求）：
解码 header，看 `alg` 和 `kid`：
- `alg=HS256` → Step 1（弱密钥）
- `alg=RS256` → Step 2（混淆，先确认有 jwks 端点）
- header 里有 `kid`/`jku`/`x5u` → Step 3（只在服务端信任时）

#### Step 1 — HS256 弱密钥
试几个常见弱密钥（secret / password / 123456 / 公司名 / 项目名）签一个改过 role 的 token，1 个请求：
- 200 接受 → 命中（弱密钥）
- 401 → NO 停（密钥不弱，别跑 hashcat 大字典）

#### Step 2 — RS256 → HS256 混淆
先确认公钥来源，2 个请求：
1. `curl /.well-known/jwks.json` 或 `/api/keys` → 有 jwks 端点才继续；无 jwks 端点 → NO 停
2. 用公钥当 HMAC 密钥签 `alg=HS256` 的 token → 200 接受=混淆成功；401=NO 停

#### Step 3 — kid / jku 注入
只在服务端信任 header 内 kid 时才试（先改 kid 发一次看是否影响密钥选择）：
- 服务端忽略 kid → NO 停（不白试路径遍历 / SQL 注入 kid）
- 服务端按 kid 取密钥 → 才试 kid 路径遍历 / jku 指向攻击者

### 工具

jwt_tool（`-C` 弱密钥、`-X k` 混淆）；手动 base64 解码先看 alg。

### 证据 / 不要做的事

- **证据**：改 role 前后 token 对比 + 200/401 响应。
- **禁**：拿到伪造 token 后登录真实管理员账号。
- **禁**：hashcat 大字典爆破（弱密钥试 5-10 个足够，爆破是浪费时间）。
- **禁**：无 jwks 端点还硬试 RS→HS 混淆。

---

## OAuth — redirect_uri / state / token 窃取

> 视角：黑盒。**判断流程优先，payload 靠现场构造，不背。**

### 排他声明

仅当目标是 OAuth 流程（redirect_uri / client_id / state / authorization_code）时用本 skill。

- 无 OAuth 上下文的纯开放重定向（`url` / `next` / `return` 参数跳转）→ ssrf skill
- JWT 形式的 token 问题 → jwt.md

### 一句话说清

OAuth 风险 = redirect_uri 校验不严 → code / token 发到攻击者域 → 接管账号。

### 判断流程（★ 核心）

#### Step 1 — 判 redirect_uri 校验模式
3-4 个请求（发起授权请求，改 redirect_uri）：
- 改 `redirect_uri=https://evil.com` 完全接受 → **无校验**，直接拿 code（P0）
- 只接受 target.com 前缀但允许子路径 → 测 `https://target.com.evil.com` / `https://target.com/redirect?url=evil.com`（前缀 / 解析差异绕过）
- 精确匹配白名单 → NO 停（校验严格）

#### Step 2 — state 缺失 / 可预测
1 个请求：
看授权请求是否带 `state`：
- 无 state / state 固定 → CSRF 绑定攻击（用自己的 code 构造 callback 链接发给受害者）
- 每次随机 state → NO 停

#### Step 3 — token 窃取（implicit flow / Referer）
观察 token 位置：
- token 在 URL fragment → 看 callback 页有无外链（Referer 泄露）
- 验证能拿到"他人" code / token 才算，拿到自己 code 不算

#### Step 4 — 停损
- redirect_uri 无校验证明到"evil.com 收到 code"即停，只对自己两个账号。
- 不诱导真实用户点恶意链接。

### 工具

Burp Repeater 改 redirect_uri；Burp Collaborator 验证 code 外带。

### 证据 / 不要做的事

- **证据**：授权请求 + evil.com 收到 code 的日志。
- **禁**：抓真实用户 code / 诱导真实用户点击。
- **禁**：纯开放重定向（无 OAuth 上下文）当 OAuth 漏洞报（去 ssrf）。
- **禁**：scope 越权请求 admin 权限实际调用（只证明到"能请求"）。

---

## SAML — 签名验证绕过

> 视角：黑盒。**判断流程优先，payload 靠现场构造，不背。**

### 排他声明

仅当目标是 SAML SSO（`<saml:Response>` / `SAMLResponse` / SSO Federation）时用本 skill。

- XXE 注入 → rce skill
- OAuth / JWT → 各自 skill

### 一句话说清

SAML 风险 = SP 信任断言但没验证签名 → 篡改 NameID 提权。

### 判断流程（★ 核心）

#### Step 1 — 删签名重发（判 SP 是否验签）
2 个请求：
1. 拦截 `POST /saml/acs` 的 SAMLResponse，base64 解码
2. 删掉整个 `<ds:Signature>` 块，改 NameID 为 admin，重新 base64 编码重发
- 200 + 登录成功（成为 admin）→ **SP 不验证签名**（P0）
- 401 / 拒绝 → NO 停（SP 验签；XSW 包装需 SAML Raider 深挖，多数目标到此即停）

#### Step 2 — 停损
- 确认不验签即停，改回原 NameID，不影响真实用户。
- XSW（签名包装）只在目标价值极高时才用 SAML Raider 试。

### 工具

SAML Raider（Burp 插件，XSW 攻击类型 1-8）；xmlstarlet 删节点。

### 证据 / 不要做的事

- **证据**：原 SAMLResponse vs 删签名改 NameID 后的响应（200 登录成功）。
- **禁**：以 admin 身份操作真实后台（登录成功即停）。
- **禁**：SAML XXE（去 rce skill）。
- **禁**：重放真实用户的有效 SAMLResponse（只用自己的断言）。

---

## 通用认证 — 登录 / 密码重置 / 2FA / 记住我

> 视角：黑盒。**判断流程优先，payload 靠现场构造，不背。**

### 排他声明

仅当目标是"认证流程本身"的逻辑缺陷时用本 skill。

- SQL 注入绕登录 → sqli
- strcmp 数组绕过 / 类型混淆绕登录 → logic-flaws
- 验证码空值 / 删除参数 → logic-flaws
- Shiro 枚举 / 反序列化 RCE → rce
- XFF 伪造绕过限频 → api-rest（速率限制）

### 一句话说清

认证漏洞 = 登录 / 重置 / 2FA 流程里有一步可被跳过或篡改。

### 判断流程（★ 核心）

#### Step 1 — 定位流程段
看到登录 / 注册 / 密码重置 / 2FA / 记住我，先定位是哪一步：输入凭据 → 验证 → 发凭证（token/cookie）→ 用凭证。每步都可能被跳过或篡改。

#### Step 2 — 密码重置投毒（Host 头）
1 个请求：
`POST /forgot-password` 带 `Host: evil.com`（或 `X-Forwarded-Host: evil.com`）
- 重置邮件里的链接指向 evil.com → **投毒确认**（受害者点链接 → token 泄露给攻击者）
- 链接仍是 target.com → NO 停

#### Step 3 — 2FA 绕过
2 个请求：
1. 正常登录到 2FA 页（拿到 session）
2. 不输 OTP 直接 `GET /dashboard`（带 session）
- 200 直接进 → **2FA 可跳过**
- 重定向回 2FA → NO 停（服务端强制校验）

#### Step 4 — 记住我 Cookie 可逆
1 个动作：
解码 `remember` cookie（base64 / URL 解码）看结构：
- 明文 / 可逆（`user:expiry:hash` 用弱 hash 或可预测）→ 可伪造
- 加密且密钥不可知 → NO 停

#### Step 5 — 停损
- 重置投毒只证明到"邮件链接指向 evil"，不真发邮件给真实用户。
- 2FA 绕过只在自己测试账号。
- 记住我伪造只证明到"能构造出 admin cookie 结构"。

### 工具

Burp Repeater 改包；curl 带 header 测投毒。

### 证据 / 不要做的事

- **证据**：投毒前后邮件链接对比 + 2FA 跳过前后响应。
- **禁**：真发密码重置邮件给真实用户。
- **禁**：爆破 OTP / 验证码（先测有没有速率限制，有就别爆）。
- **禁**：用伪造 cookie 登录真实账号。
- **禁**：把 SQLi / strcmp / XSS 绕登录归到本类（去对应 skill）。
