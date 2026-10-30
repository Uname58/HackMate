# CSRF / Form 判定规则

## 判断顺序
1. 确认请求修改状态且参数可预测。
2. 检查是否有 CSRF token。
3. 无 token 或 token 弱校验时，直接测跨源伪造。
4. 被拒则进入 Referer/Origin 校验判定。
5. 仍被拒则检查方法、Content-Type、参数解析差异。
6. 全部失败则停止，换攻击面。

---

## 1. 确认目标请求
- 信号：改密、改邮箱、转账、加管理员、更新资料等状态修改请求。
- 怎么做：
  - 记录方法、URL、参数、Cookie、Referer/Origin。
  - 参数完全已知或可枚举，无随机动态值。

---

## 2. 无 token 时直接测 CSRF
- 信号：请求中没有 `csrf_token`、`token`、`_csrf`、`authenticity_token` 等参数。
- 怎么做：
  1. 用受害会话 Cookie 重放该请求，先不带 Referer，再带同源 Referer。
  2. 直接成功 → 无 CSRF 防护，直接构造表单/请求。
  3. 被拒 → 进入 Referer/Origin 校验判定。
- 最小示例：`?password_new=X&password_conf=X&Change=Change`

---

## 3. 有 token 时测弱校验
- 信号：请求携带 token 类参数。
- 怎么做：
  1. 删除 token 参数。
  2. token 置空、任意值、复用同一会话旧 token。
  3. token 与 Cookie 同名/同值，尝试同时设置 Cookie 和参数为任意相同值。
  4. token 可预测：时间戳、递增 ID、hash(固定信息) 等，按此生成。
- 任一通过 → 可 CSRF，携带可接受 token 继续。

---

## 4. Referer/Origin 校验判定与绕过
- 信号：
  - 无 token 但无 Referer/Origin 被拒。
  - 响应提示 `That request didn't look correct.`、`invalid referer`、`invalid origin` 等。
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
  1. 改 GET 为 POST，或 POST 改 GET。
  2. 尝试 `Content-Type: text/plain`、`application/x-www-form-urlencoded`、`multipart/form-data`。
  3. 尝试参数顺序变化、冗余参数、同名参数。
- 仅当原 payload 有效时继续，每次只改一个变量。

---

## 6. 停/换思路信号
- 删除/替换/复用 token 均返回 403 或 token invalid，且 token 与 session 强绑定。
- Referer/Origin 强校验为精确同源，子串包含、空头、跨源变体均无效。
- 请求需要自定义 Header（如 `X-Requested-With`）且无法通过浏览器跨源发送。
- 操作有二次认证且当前无法绕过。