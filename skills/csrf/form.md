# CSRF / Form 判定规则

## 判断顺序
1. 确认请求修改状态、参数可预测，并逐字节复制原始请求（参数名、值、大小写、submit/button 值）。
2. 检查是否有 CSRF token。
3. 无 token 时，测试无 Referer、同源 Referer、跨源 Referer 三种情况。
4. 任意 Referer 都成功 → 直接生成跨源可触发 payload。
5. 有 token 或对 Referer/Origin 有区分 → 进入弱校验与 Referer/Origin 绕过判定。
6. 全部失败则停止，换攻击面。

---

## 1. 确认目标请求
- 信号：改密、改邮箱、转账、加管理员、更新资料等状态修改请求。
- 怎么做：
  - 记录方法、URL、参数、Cookie、Referer/Origin。
  - 参数完全已知或可枚举，无随机动态值。
  - 参数值必须逐字节复制真实请求，包括大小写、默认值、submit/button 的 name/value；不要自行修改 submit 值或省略“无关”参数。
  - 用实际目标域名/IP/IP:port，不使用 `<victim-host>` 等占位符。

---

## 2. 无 token 时测跨源可触发
- 信号：请求中没有 `csrf_token`、`token`、`_csrf`、`authenticity_token` 等参数。
- 怎么做：
  1. 用受害会话 Cookie 重放该请求，分别发送：无 Referer、同源 Referer、跨源 Referer（如 `http://evil.example.com/`）。
  2. 三者均成功（返回 200 且状态修改生效）→ 完全无 CSRF 防护。
  3. GET 请求：攻击 payload 直接是完整 URL，放入 `<img src=...>`、`<script>location=...</script>` 或 `window.open`，受害者浏览器会自动携带 Cookie。
  4. POST 请求：生成 auto-submit 表单（`<form method=POST action=...><input ...></form><script>document.forms[0].submit()</script>`）。
  5. 最终 payload 必须使用实际目标地址，不保留占位符；说明在受害者已登录浏览器中触发。
- 最小示例：GET `/xvwa/vulnerabilities/csrf/?passwd=hacked1&confirm=hacked1&submit=submit`

---

## 3. 有 token 时测弱校验
- 信号：请求携带 token 类参数。
- 怎么做：
  1. 删除 token 参数。
  2. token 置空、任意值、复用同一会话旧 token。
  3. token 与 Cookie 同名/同值，尝试同时设置 Cookie 和参数为任意相同值。
  4. token 可预测：时间戳、递增 ID、hash(固定信息) 等，按此生成。
- 任一通过 → 可 CSRF，复用第 2 步生成跨源 payload。

---

## 4. Referer/Origin 校验判定与绕过
- 信号：
  - 无 token 但无 Referer/Origin 被拒。
  - 跨源 Referer 被拒但同源通过。
- 决策步骤：
  1. 先不带 Referer/Origin 发一次，记录是否被拒。
  2. 带同源 Referer/Origin 发一次，确认可通。
  3. 带明显跨源 Referer/Origin（如 `http://evil.example.com/`）发一次。
  4. 若跨源被拒，但 Referer URL 路径、参数或主机部分包含目标主机名/SERVER_NAME 时通过，说明只做子串包含校验。
  5. 继续尝试变体定位包含位置：
     - `http://attacker.com/<target-host>/`
     - `http://<target-host>.attacker.com/`
     - `http://attacker.com/?<target-host>`
  6. 若 Origin 头只检查非空或包含目标，尝试对应 Origin 变体。
  7. 一旦确认绕过方式，构造 CSRF 页面，使请求携带满足条件的 Referer。
- 最小示例：服务端执行 `stripos(REFERER, SERVER_NAME)` 时，`Referer: http://evil.example.com/localhost/` 中因路径包含 `localhost` 而通过。

---

## 5. 方法/Content-Type/参数兼容性
- 信号：原请求被拒，但可能存在解析差异。
- 怎么做：
  1. 原请求为 GET 且成功时，无需改方法；若 POST 被拒，可尝试改 GET。
  2. 尝试 `Content-Type: text/plain`、`application/x-www-form-urlencoded`、`multipart/form-data`。
  3. 尝试参数顺序变化、冗余参数、同名参数。
- 仅当原 payload 有效时继续，每次只改一个变量。

---

## 6. 停/换思路信号
- 删除/替换/复用 token 均返回 403 或 token invalid，且 token 与 session 强绑定。
- Referer/Origin 强校验为精确同源，子串包含、空头、跨源变体均无效。
- 请求需要自定义 Header（如 `X-Requested-With`）且无法通过浏览器跨源发送。
- 操作有二次认证且当前无法绕过。