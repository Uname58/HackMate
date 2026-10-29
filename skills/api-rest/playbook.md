# REST API / WebSocket 判断流程

## REST API — BOLA / Mass Assignment / 速率限制 / CORS

> 视角：黑盒，双账号交叉对比。**判断流程优先，payload 靠现场构造，不背。**

### 排他声明

仅当目标是 REST API 端点时用本 skill。

- eyJ 三段 token（JWT）→ oauth-saml-jwt skill
- `/graphql` 端点 → graphql skill
- 纯 IDOR（改 URL 里 ID 访问他人资源）→ idor skill
- SQL / NoSQL / LDAP / 命令注入 → sqli / rce skill

### 一句话说清

REST API 越权 = 服务端信任"客户端传来的 ID / JSON 字段"，没做对象级或字段级校验。

### 判断流程（★ 核心，按顺序执行，任一步 NO 就停）

#### Step 1 — BOLA（对象级越权，最高价值）
3 个请求：
1. 账号 A 创建资源拿 ID（`POST /api/orders` → `{"id":123}`）
2. 账号 B 用自己 token `GET /api/orders/123`
3. 看响应：
   - 200 + 返回 A 的资源数据 → **BOLA 确认**
   - 403 / 404 / 返回空 → NO，停（授权正常）

要点：必须"B 拿到 A 的数据"（两账号各建一个资源，交叉读），不是"B 拿到自己的 123 号资源"。

#### Step 2 — Mass Assignment（字段级越权）
先探再注，2 步：
1. POST 正常字段（`{"name":"x","email":"x@x"}`）→ 看响应是否回显 `role` / `isAdmin`
   - 不回显 → 注入大概率无效，NO 停（别盲注）
   - 回显（如 `"role":"user"`）→ 继续
2. 注入 `"role":"admin"` / `"isAdmin":true` → 对比：
   - 响应 role 变 admin，或之后 `GET /me` 返回 admin → **命中**
   - 200 但字段没生效（仍回显 user）→ 后端有白名单，NO 停

#### Step 3 — 速率限制缺失/绕过
先确认再绕，2 步：
1. 串行发 N 次（如 20 次）同一请求 → 确认是否 429
   - 从不 429 → 直接报"无速率限制"（本身是漏洞）
   - 稳定 429 → 继续测绕过
2. 绕过头：`X-Forwarded-For` 轮换 / `X-Real-IP` / 换 API Key → **稳定 200 才算绕过**，1 次成功是巧合

#### Step 4 — CORS 配置错
1 个请求 + 1 个响应头判断：
发 `Origin: https://evil.com` → 看响应 `Access-Control-Allow-Origin`：
- 回显 `https://evil.com` 且 `Access-Control-Allow-Credentials: true` → **可窃取带凭据响应**
- 回显 `*` 且无 Credentials → 低危（无凭据）
- 无 ACAO 头 → NO 停

### 工具

curl / Burp Repeater 做双账号对比；BOLA 批量枚举用 Burp Intruder。

### 证据 / 不要做的事

- **证据必备**：双账号（A 建 B 读）交叉请求 + 响应差异截图，报告写清"B 的 token 读到了 A 的 id=123"。
- **禁**：枚举他人真实资源（ID 遍历只在自己两个测试账号的资源间做）。
- **禁**：Mass Assignment 提权后进 admin 后台操作，`GET /me` 看到 role=admin 即停。
- **禁**：速率绕过打到真实用户（只在自己账号上验证 429→200）。
- **限**：CORS 只证明到"响应头允许任意 Origin"，不真写 PoC 偷 cookie。

---

## WebSocket — CSWSH / 认证授权绕过

> 视角：黑盒。**判断流程优先，payload 靠现场构造，不背。**

### 排他声明

仅当目标是 `wss://` / `ws://` 端点时用本 skill。

- REST 端点 → api-rest/rest-api.md
- WebSocket 消息里的 SQL / XSS / 命令注入 → 各自 skill（sqli / xss / rce）

### 一句话说清

WebSocket 特有风险 = 握手只验证一次（Origin / 认证），连接建立后不再校验 → 跨站劫持（CSWSH）+ 频道越权订阅。

### 判断流程（★ 核心）

#### Step 1 — 判 CSWSH（握手不验 Origin）
2 个请求：
1. `curl -i -N -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" -H "Origin: https://evil.com" https://target/ws`
2. 看握手响应：
   - `101 Switching Protocols` 且不校验 Origin → **CSWSH 确认**（恶意页可带受害者 cookie 连上来）
   - 403 / 拒绝 evil Origin → NO 停

#### Step 2 — 连接后认证缺失
1 个请求 + 观察：
带自己低权限 token 建立连接 → 尝试订阅他人频道（`subscribe: user.{otherId}.messages`）
- 收到他人频道消息 → **频道越权**
- 被拒 → NO 停

#### Step 3 — 停损
- 证明握手不验 Origin 即停，不真写 PoC 窃取数据。
- 频道越权证明到"收到 1 条非本人频道消息"即停。

### 工具

websocat 建连测 Origin；Burp 的 WebSocket 标签重放消息。

### 证据 / 不要做的事

- **证据**：握手请求/响应原样（Origin: evil.com → 101）+ 频道订阅响应。
- **禁**：真用恶意页劫持受害者会话（只证明握手 101 即可）。
- **禁**：遍历订阅所有频道拖数据（1 个他人频道即可）。
- **禁**：把 WebSocket 消息里的注入当 WebSocket 漏洞报（SQLi 归 sqli、XSS 归 xss）。
