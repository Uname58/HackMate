# 任意 X 子授权（越权）

> 视角：黑盒，已登录低权账号。**判断流程优先，payload 靠现场构造不背。**

## 排他声明
仅当「用合法低权身份执行高权操作 / 访问他人资源」时用本 skill。
- 维度内改 ID 读他人资源（A 改 id=B 看 B 数据）→ logic-flaws 的 IDOR
- 完全无凭证 / 默认凭据 / 管理面直暴露 → unauth-access
- 并发竞态（券双花 / 余额超扣）→ race-conditions
- 本 skill 只管：用合法低权 token 执行本应高权才能做的操作（任意账号 / 任意操作 / 任意修改 / 任意删除 / 任意注册）

## 一句话说清
越权 = 请求合法但服务端不校验「身份 vs 权限」。任意账号(86.4% 高危)≈RCE，任意操作(72.5%)≈全站管理员。

## 判断流程（★ 核心，按顺序执行，任一步 NO 就停）

### Step 1 — 双账号 + 三角色测序（2-3 个请求定位越权维度）
准备账号 A/B（注册级）+ C（能拿到就商家/审核员）。对每个写/删/批准接口依次：
1. A 调自己资源（基线，200 = 接口可用）
2. A 调 B 资源（→ 维度内 IDOR，转 logic-flaws）
3. A 调 C/admin 才能调的接口（→ 本 skill 的任意操作）
4. 完全不带 token 调（→ unauth-access）
结论：A 调 admin 接口返回 200+正常数据 = 疑似漏鉴权进 Step 2；全程 401/403 = 有鉴权，停。

### Step 2 — 状态码语义（1 个请求判下一步）
- 200 + 正常数据 → 立刻测越权（进 Step 3）
- 200 + {"error"} → 改参数继续
- 401 / 403 → 有鉴权，试 bypass 头（X-Forwarded-For / 双 Host / 路径变体），仍 401/403 = 停
- 404 → 路径错；405 → 换方法；500 → 看报错找内部路径

### Step 3 — 任意账号（最高价值 86.4%，命中即停）
核心：篡改身份字段看能否接管。
- 密码/sign 字段置空 / null / 全 0 / 删除：POST /api/login {"phone":"victim","sign":""} → 200+token = 接管
- SSO 回调改 username=admin 重发 → 200+token = 接管
- 一键登录改 phone 字段 → 登入 victim = 接管
- Cookie/Header 直接信任：?userAccount=admin / Cookie: isAdmin=1 → 进后台 = 接管
**终点判定：置空/null/全0/删除后仍 401/403 → 停（服务端真校验）。拿到 victim token 且 /api/me 返回 victim 资料 = 确认，立即停，不登录真实用户。**

### Step 4 — 任意操作 / 任意修改（72.5%，最易被低估）
接口名含 approve/audit/verify/publish/refund/ban/deploy/sendCard 等 → 必测。
- 自审自批：A 提交申请 → 同 A 调 /admin/xxx/approve → 状态 pending→approved = 确认
- 批量执行：普通账号调 /admin/users/banAll、/api/recharge/genCard → 200 = 确认
- mass-assignment 提权：注册/资料更新 body 加 role=admin / is_admin=true → 响应回显 role=admin 或 /api/me 显示 admin = 确认
**终点判定：接口 200 且返回 success / 状态翻转 = 确认停。只做「接口能调通 + 200」证明，不实际发卡/退款/删数据。**

### Step 5 — 停损（任意删除 / 写类操作只证明不做）
- 任意删除：只用 A/B 互删证明「A 能删 B」，永不删真实数据；无法双账号证明时只截接口暴露 + 不带 token 看 401/403，不触发。
- 确认越权后只用 /api/me 看 role 字段，不进 admin 后台实际操作。

## 工具
无固定工具。接口发现命中率：前端 JS 拆包 / Swagger / APP 抓包 > Wayback > 报错页。

## 证据 / 不要做的事
- 报告三要素：①基线（A 正常调）②越权证明（A 拿到 B 资源 / A 调通 admin 接口，截图）③影响（任意账号≈RCE）。
- 禁：用任意账号登录真实用户看数据——永远用研究员两个测试号互测。
- 禁：任意删除真实数据、发起真实退款/转账、改全站公告/邮件模板——证明到「200/success」即停。
- 禁：注册用 admin@victim.com 高权限账号——用研究员自己的邮箱后缀。
- 状态码快表记牢：200+数据=漏鉴权候选；401/403=有鉴权。
