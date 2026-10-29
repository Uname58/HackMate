# XSS 判断流程

## 反射型 XSS

> 视角 + 判断流程优先，payload 靠现场构造（按反射上下文现场搭），不背。

### 排他声明
仅当「输入立即回显在 HTML 响应、且落点在 HTML/JS 上下文可执行」时用本 skill。

- 反射落模板表达式（`{{7*7}}` 出 49）→ ssti
- Location/redirect 参数反射跳转 → 开放重定向
- HTML 注入但无法执行 JS（CSP 卡死）→ 单独归类，别硬凑 XSS
- 回显在 JSON/XML 但非 HTML 渲染 → 先看 Content-Type 是否 text/html

### 一句话说清
反射型 XSS = 输入 → 服务端回显 → 浏览器执行。核心是「定反射上下文」再「按上下文 breakout」，不是堆 payload。

### 判断流程（★ 核心，任一步 NO 就停）

#### Step 1 — 三态判定（先定输入可不可控、可不可执行）

每参数一个唯一 canary（`xsstest12345`），看反射后是哪种态：

- **raw**（原样反射）→ 可能可执行，继续 Step 2
- **encoded**（实体/URL 编码，`<`→`&lt;`）→ 不执行，除非下游再解码一层
- **executable**（真执行）→ 唯一可报的态
- 连续 5 个 breakout payload 都不执行 → WAF/编码死锁，**放弃该参数**，别换更多 payload 硬试

#### Step 2 — CSP 预判（别在死路上烧时间）

先读响应 CSP 头 + `Content-Type`：

- 无 CSP / 有 `unsafe-inline` → 内联全通，进 Step 3
- `script-src 'self'` 无 JSONP → 降级为 HTML 注入/无脚本（dangling markup / 表单劫持），**别浪费时间试 onerror**
- `require-trusted-types-for 'script'` → HTML sink 大多死，找非 TT sink 或换点

#### Step 3 — 确认阈值

真实浏览器弹 alert 且 **console 无解析错** 才算成立。payload 出现在源码 / 只在 JS 字符串内 / `<title>`/`<textarea>` 内 = 不算。证明同源用 `alert(document.domain)`，不用 `alert(1)`。

#### Step 4 — 时间盒

单参数 10 分钟未确认 → 换下一个参数/输入点。别在一个死参数上耗到超时。

### 探针流程（定上下文）

1. 每输入点一个唯一 canary（+ 参数后缀）归因反射。
2. 对比 raw 响应 vs 渲染 DOM：DOM-only = 客户端 sink，转 dom_xss。
3. 字符探针 `' " < > / \ & { } ( ) ; : =` 逐个记 raw/实体/剥离/转义/截断。
4. 长度 20/200/2000 找截断点，payload 放最前。
5. 解码深度：`%3c`/`%253c`/`&#x3c;`/`&lt;` 数解码轮数。
6. 读反射点前后字节，定死上下文（文本/属性/JS 字符串/事件处理器/注释），按上下文现场构造最小 payload。
7. 真实浏览器 + console 打开确认执行。

### 证据 / 不要做的事

- 只报「可执行」态；raw/encoded 态不是 XSS。
- 用 `alert(document.domain)` 证明同源，别 exfil 真实 cookie。
- `Content-Type` 非 text/html 且 nosniff → 现代浏览器不执行，别报。
- Location 反射 = 开放重定向不是 XSS。
- 自测 DOM 里 `el.innerHTML=payload` 能弹 ≠ 真实路径可达（中间可能有 encodeURIComponent/textContent 截断）。
- 最终 PoC 要在目标真实源/登录态复现，抓精确请求。

---

## 存储型 XSS

> 视角 + 判断流程优先，payload 靠现场构造，不背。

### 排他声明
仅当「输入存进服务端、后续被其他人（admin/客服/其他用户）访问并回显执行」时用本 skill。

- 只在自己页面执行 = self-XSS，不是 stored，弃。
- 反射落点 → reflection_xss.md
- 客户端 sink → dom_xss.md

### 一句话说清
存储型 XSS = 持久化恶意 JS，每次访问都执行，危害最大（打进后台=接管）。

### 判断流程（★ 核心，任一步 NO 就停）

#### Step 1 — 注入点枚举（挑会进别人视图的字段）

评论、display name、bio、订单备注、工单、私信、文件名、EXIF；headers（User-Agent/Referer/X-Forwarded-For）进后台日志；二次落点（邮件模板/PDF 导出/审计日志/通知中心）。每字段唯一 token `bio-a1b2c3` + 夹字符暴露编码行为。

#### Step 2 — 落点定位 + 三态判定

低权限注入，高权限账号（admin/客服）浏览所有相关页面。canary 前后 30 字符定上下文；同时抓 API 原始响应 vs 渲染 DOM（一致=服务端渲染；DOM 变=前端 sanitizer/sink）。判定三态（raw/encoded/executable），只报可执行。

#### Step 3 — 确认阈值（排除 self-XSS）

换账号 + 无痕浏览器访问同一 URL 仍执行 = 真 stored。canary 被实体编码（`&lt;`）= 不执行，别写报告（除非确认下游再解码）。

#### Step 4 — 停损

`alert(document.domain)` 证明同源即停，不 exfil 真实 cookie。

### 证据 / 不要做的事

- 换账号复现才算 stored；只在提交者自己页面 = self-XSS，弃。
- 渲染有延迟/队列：注入后等 1–5 分钟多页刷新。
- DB 字段截断：payload 放最前。
- 存时转义一次取时再转义 = 双层编码，构造嵌套实体，别当失败。
- 只在邮件客户端/PDF 导出/移动端/后台审核页渲染的字段最易漏。
- 不 exfil 真实 cookie。

---

## DOM XSS

> 视角 + 判断流程优先，payload 靠现场构造，不背。

### 排他声明
仅当「不可信数据经客户端 JS 写入危险 sink（不经过服务端）」时用本 skill。

- 服务端回显反射 → reflection_xss.md
- 存储回显 → stored_xss.md

### 一句话说清
DOM XSS = 客户端 JS 把不可信数据（location.*/referrer/window.name/postMessage/storage）写进危险 sink（innerHTML/document.write/eval/`.href=`）→ 执行。

### 判断流程（★ 核心，任一步 NO 就停）

#### Step 1 — 找 source → sink 通路

grep 源码 `innerHTML|document\.write|eval\(|\.href=|v-html|dangerouslySetInnerHTML|{@html}`，看哪些 `location.*`/`window.name`/`postMessage.data` 流到 sink。打 sink 断点比追 source 快：`debug(document.write)`、`Object.defineProperty(HTMLElement.prototype,'innerHTML',{set(){debugger}})`。

#### Step 2 — 确认 sink 上下文

sink 是 HTML 文本（innerHTML）/属性/JS 字符串/URL 四选一，选错必然不触发。`innerHTML` 里 `<script>` 永不执行、detached 节点 onerror 不触发（必须 attach 到 document）。

#### Step 3 — 确认阈值 + 停损

真实浏览器 alert + console 无解析错才算。`alert(document.domain)` 证明同源即停。

### 证据 / 不要做的事

- console 手测 `el.innerHTML=payload` 能弹 ≠ 真实路径可达（路上可能被 encodeURIComponent/textContent 截断），每个 payload 回真实 sink 验证。
- fragment 不经服务端，但 CSP 头/后端编码仍生效，别忽略。
- `src=x` 同源 SPA 回退返回 200 时 onerror 不触发 → 用 `src=//0`。
- `javascript:` 前已拼 `https://` 或协议白名单 → 失效。
- innerHTML 的 `<script>` 永不执行，别死磕。

---

## Caution — 坑 / 预警

> 记「别踩什么」。与 skill.md（记「怎么做」）互补，别互相抄。

### 反射型 XSS 常见坑
- `htmlspecialchars` 没加 `ENT_QUOTES` → 单引号没转义，属性内单引号 breakout 仍可打。
- `str_replace` 大小写敏感（漏 `strtolower`）→ 大小写混淆绕过。
- `str_replace` 替换成空（而非占位符）→ 双写 / 嵌套关键字绕过。
- header 值（Referer / User-Agent / Cookie）回显没消毒 → 头注入。
- 属性上下文 vs 文本节点上下文：转义需求不同，别用同一套 payload 硬套。

### 测试方法论坑
- 别只测 GET 参数，POST 参数、header、hidden field 一样可能是反射点。
- 探针要用唯一标记（如 `xssTEST123`），否则反射点多时分不清哪个对应哪个。
- 判断 XSS 成立要「真执行」，不是「payload 出现在源码里」——**alert 弹了才算**。
