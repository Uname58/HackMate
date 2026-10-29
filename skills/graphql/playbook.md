# GraphQL

> 视角：黑盒。**判断流程优先，payload 靠现场构造，不背。**

## 排他声明

仅当端点确认是 GraphQL 时用本 skill。

- 判 GraphQL 只需一个 `{__typename}`，非 GraphQL 立刻离开
- REST 端点 → api-rest skill
- query 字段值里的 SQL / NoSQL 注入 → sqli skill

## 一句话说清

GraphQL = 一个端点，所有 query / mutation 走它。特有风险：Introspection、字段级授权缺失、别名限频、深度递归 DoS。

## 判断流程（★ 核心，Step1-5）

### Step 1 — 判是否 GraphQL
1 个请求：
`POST /graphql {"query":"query{__typename}"}`
- 200 + `{"data":{"__typename":"Query"}}` → 是 GraphQL，继续
- 其他（HTML / 404 / 非 GraphQL 报错）→ NO 停，立刻离开

### Step 2 — Introspection 是否开启
1 个请求：
`{"query":"{__schema{types{name}}}"}`
- 返回完整 types 列表 → 开启，拉 schema 找敏感字段（`password` / `ssn` / `creditCard` / `apiKey` / `balance`）
- 返回 `"message":"...not allowed"` 等 → 关闭，判断目标是否值得用 clairvoyance 推断（不值 → NO 停）

### Step 3 — 字段级越权（需第二账号）
不能只凭"字段名带 password"就报——需双账号对比同一 query：
1. 账号 A `query{user(id:A){email phone}}` → 基线
2. 账号 A 改 `query{user(id:B){email phone}}`（B 是第二测试账号）
3. 返回 B 的数据 → **嵌套 IDOR / 字段越权确认**；返回错误 → NO 停

### Step 4 — 别名爆破（绕限频）
1 个请求判断：
`mutation{a:login(user:"admin",pass:"x1"){token} b:login(...x2)... z:login(...x26)}`
- 返回 26 个不同结果（每个 alias 独立执行）→ **限频绕过确认**
- 返回 rate-limit 错误 / 只 1 个结果 → 被拦，NO 停

### Step 5 — 停损
- 拿到 schema 但无敏感字段 → 停（不硬造敏感字段）
- 深度递归 DoS 只证明到"响应变慢/超时"，不真打瘫
- 别名爆破只在自己账号，禁撞真实账号

## 工具

clairvoyance（无 introspection 的 schema 推断）、graphql-cop。

## 证据 / 不要做的事

- **证据**：`{__typename}` 确认 + schema 里的敏感字段名 + 双账号响应差异截图。
- **禁**：用别名爆破真实账号密码（只自己测试号）。
- **禁**：深度递归 DoS 实际打瘫服务（10 层、几次请求证明即可）。
- **禁**：嵌套 IDOR 拖大量数据（3 个不同 ID 样本足够）。
- **禁**：introspection 拿到 schema 后全量 dump。
