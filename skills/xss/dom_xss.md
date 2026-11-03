# XSS / DOM XSS

## 0. 先判定 sink 与可用字符
- 信号：可控值落在 HTML 文本节点、属性值、JS 字符串、`javascript:` URL 或 DOM sink。
- 做法：先发探针 `x"'>`，记录 `<` `>` `"` `'` 是保留、删除还是编码；再测关键 token（`on`、`script`、`href`、`()`、`&apos;`）的大小写敏感和过滤情况。
- 停/换：如果反射值被完整实体编码且无解码差异，换点。

## 1. 属性值内 + 大小写敏感替换
- 信号：输入进入 `value="..."` 或 `<a href="...">`；`on`、`script`、`href` 被替换但只匹配某一种大小写；`<` `>` `"` 保留。
- 做法：
  1. 用 `"><` 确认能否闭合属性并逃出标签。
  2. 不要只依赖原 `on*` 属性；闭合后插入新标签或属性。
  3. 对被过滤 token 做大小写混写：`hRef`、`javaScript:`、`oNfocus`，先确认一个混写不被替换。
  4. 优先选不依赖括号的事件或协议触发。
- 停/换：如果替换大小写不敏感，放弃该 token；如果 `<` `>` 被删，转属性注入。
- 最小示例：`"><a hRef="javascript:alert(1)">x</a>`

## 2. 仅放行非自触发事件，且判定要求无交互
- 信号：黑名单只放行 `<body onresize>` 这类需要外部条件触发的事件组合；目标页可被 iframe 嵌入；判定要求无交互。
- 做法：
  1. 把注入载荷放到目标页 URL 的查询参数中，作为 iframe 的 `src`。
  2. 在外层 iframe 标签上写 `onload=this.style.width='100px'`，改变 iframe 宽度触发内层 body 的 resize。
  3. 内层只使用目标页放行的标签/事件，并调用判定要求的函数，如 `print()`。
- 停/换：如果目标响应禁止 iframe 嵌入或 CSP 阻止，换点；如果 iframe 尺寸变化不触发事件，停止。
- 最小示例：`<iframe src="TARGET/?search=<body onresize=print()>" onload=this.style.width='100px'></iframe>`

## 3. javascript: URL sink 中，输入位于 JS 单引号字符串且括号被过滤
- 信号：输入被拼进 `body:'...'` 这类 JS 字符串/对象内；`(` `)` `\` `[` `]` 被过滤，但 `'` `{` `}` `=` `>` `,` `/` `*` `:` 可用；最终为 `javascript:` 链接。
- 做法：
  1. 用 `'}` 或 `'` 闭合当前字符串和对象/参数，再用 `,` 继续表达式。
  2. 禁止直接 `alert()` 时，用无需括号的 `throw/**/onerror=alert,1337` 或箭头函数块/`toString` 隐式触发。
  3. 用 `/**/` 代替空格；不要依赖 `%` 字符本身，URL 编码交给请求层处理。
- 停/换：如果 `'` 也被转义或过滤，改找 HTML 实体解码差异；如果 `javascript:` 协议被拦，转普通事件属性。
- 最小示例：`'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'`

## 4. 内联 JS 字符串属性中，单引号/反斜杠转义，但 HTML 实体可解码
- 信号：输入落在 `onclick="...track('输入')..."` 的单引号字符串内；`'` 和 `\` 被转义，`"` `<` `>` 被 HTML 编码。
- 做法：
  1. 不输入字面 `'`，用 `&apos;` 生成单引号；属性值 HTML 解码后，JS 字符串即可被闭合。
  2. 闭合后再注入无额外引号的调用，如 `&apos;-alert(1)-&apos;`，保持原 JS 语法完整。
  3. 若页面要求非 alert 验证，换 `confirm`/`print`。
- 停/换：如果 `&` 被过滤或 `&apos;` 未解码，停止；如果 sink 不经 HTML 属性解码，不使用该思路。
- 最小示例：`&apos;-alert(1)-&apos;`

## 5. 双引号属性值注入 + 尖括号被删 + alert 被重写
- 信号：输入进入 `value="..."`；`<` `>` 被删除，`"` 保留；无法插入新标签。
- 做法：
  1. 用 `"` 闭合当前属性，继续写新属性：`" onfocus="confirm(1)" autofocus="`。
  2. 新事件属性值必须也用 `"` 闭合，并与尾部属性结构对齐，避免浏览器解析吞掉后续属性。
  3. 使用 `autofocus` 自触发；若 `alert` 被重写，直接调用 `confirm(1)` 或 `print()`。
- 停/换：如果 `"` 也被过滤或编码，换无引号属性注入；如果 `onfocus` 被过滤，试其他自触发事件。
- 最小示例：`" onfocus="confirm(1)" autofocus="`

## 6. DOM sink 通用切换
- 信号：可控值未出现在响应 HTML 中，而进入 `innerHTML`、`document.write`、`eval`、`location` 等 JS 调用。
- 做法：按最终 sink 上下文套用上述规则：写 `innerHTML` 当 HTML 文本/属性值处理；写 JS 字符串当 JS 闭合处理；写 `location` 当 `javascript:` URL 处理。先确认 sink 前是否经过 URL 解码或 JS 转义。
- 停/换：如果 sink 值被严格 `encodeURIComponent` 且没有二次解码，停止。