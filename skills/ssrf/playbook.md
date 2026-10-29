# SSRF 判断流程

> 视角：黑盒，判断流程优先，payload 靠现场构造，不背。

## 排他声明

仅当目标是「服务端主动发请求」时用本 skill。

- file:// 读本地文件 → path-traversal skill（本 skill 不负责读文件）
- XML 实体引用外部 URL → xxe skill
- Location / returnUrl 反射跳转 → 开放重定向
- Host / X-Forwarded-* 注入影响缓存 → 缓存投毒（非 SSRF）

---

## 一句话说清

SSRF = 让服务器替你向「它能到、你不能到」的内网/元数据发请求。验证点是「服务器确实发了请求」，不是「URL 被 echo 回来」。

## 判断流程（★ 核心，按顺序执行，任一步 NO 就停）

### Step 1 — 出网判定（先确认服务器能连外网）

发 1 个请求，把 URL 指向你自控的 OOB 接收点（自架 interactsh，别用公共 DNSLog）：

- 收到回调 → 服务器能出网，进 Step 2
- 收不到回调 → 只能「盲 SSRF」（纯靠时间/长度差猜），价值骤降；连盲测都无法区分 → **放弃，NO 就停**

### Step 2 — 回显模式判定

看 SSRF 响应体/状态码，分两类：

- **有回显**：响应直接含目标内容（内网页/文件/元数据）→ 直接读目标
- **无回显**：只能靠「响应时间差 / 长度差 / 状态码差」判端口与可达性

### Step 3 — 端口扫描（时间/长度差判定）

对候选内网 IP 逐端口发请求，用「时间差 + 长度差 + 状态码差」判端口开闭：

- 开放 vs 拒绝有稳定差异 → 记下开放端口
- **三私网段（10/8、172.16/12、192.168/16）全无差异 → 停止内网探测**（目标不在内网或过滤太死，别再烧请求）

### Step 4 — 协议降级链

按顺序试，一级走不通降下一级：

`http` → `https` → `file` → `dict` → `gopher`

http/https 通 = 基本 SSRF；file 通 = 本地读（交 path-traversal）；dict 通 = 可探测 Redis/Memcached；gopher 通 = 可构造任意 TCP 字节（打 Redis/MySQL/FastCGI）。

### Step 5 — 停损

- 拿到云元数据凭证（AWS/GCP/Azure 的 AccessKey/Token）→ **立即停**，这是 P0 证据，直接写报告
- SSRF 本身不执行命令，拿到凭证即最高价值，别继续深挖

---

## 通用绕过三件套 — UA 头 / DNS 重绑定 / 302 重定向

服务端做了 URL 白名单 / IP 校验 / 私网段过滤，但「校验时拉到的内容」与「实际请求时拉到的」不是同一份。三种绕过分别打「User-Agent 分支」「DNS 解析时间窗」「重定向跟随」。

### 1. UA 头分支绕过（头像 / 图片下载接口）

后端按 `User-Agent` 分流：内部代理/业务客户端走「无校验」分支，普通浏览器 UA 走「严格校验」分支。改 UA 成业务客户端（`go-httpclient/1.0`、`Java/1.8.0_271`、`okhttp/4.9.0`、`python-requests/2.28`、`PostmanRuntime/7.30`），看响应是否含内部域内容（304 / Location: 内网 / 内容长度异常）判断分支命中。
典型触发点：头像上传（URL 模式）、富文本「插入网络图片」、Webhook 配置、邮件附件预览、URL 链接预览。

### 2. DNS 重绑定（TOCTOU）

服务端先解析 DNS 做白名单校验，再解析发起请求，两次解析之间 DNS 记录被切换 → 校验时公网 IP、请求时内网 IP。

- 在线 rebinder：`lock.cmpxchg8b.com/rebinder.html`（自架 singularity/dns-rebind/rbndr 更稳）
- 关键：TTL 0/1 避免后端缓存；round-robin 交替返回 [公网 IP, 127.0.0.1]
- 127.0.0.1 变种（黑名单只拦字面量时）：`127.1`、`0`、`0x7f000001`、`2130706433`、`017700000001`、`[::1]`、`localtest.me`
- 何时用：后端 `parse_url + gethostbyname + 白名单 + curl_exec` 两段式；WAF 只看字面 host；AWS metadata 被字面 blacklist

### 3. 302 重定向跟随绕过

服务端只对「用户提交的 URL」做校验，但 `curl --location` / `requests follow_redirects=True` 会跟随 302 跳任意 URL。攻击者域上挂 `Location: http://127.0.0.1:6379/` 即可。
链式重定向规避协议限制：https（过协议白名单）→ http → gopher/dict/file 落点。

**三件套合体命中顺序**：UA 头找内部分支接口 → DNS 重绑定绕字面 IP 黑名单 → 302 重定向绕协议白名单 + 触发 gopher/file 落点。

## 证据 / 不要做的事

- 证明 SSRF 要「服务器确实发了请求」，用 OOB 回调 + 请求日志双向印证，别只截「URL 回显在页面」。
- 云元数据凭证到手即停，别拿凭证动生产资源（越权审计另行授权）。
- 内网端口扫描低速单发，别对生产内网开大并发。
- 别用公共 DNSLog 收敏感数据（明文共享，他人可见）；OOB 平台自架 interactsh。
