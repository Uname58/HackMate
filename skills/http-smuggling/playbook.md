# HTTP Request Smuggling

> 视角 + 判断流程优先，payload 靠现场构造（CL/TE 头现场拼），不背。

## 排他声明
仅当目标是「前置代理 + 后端对 CL/TE 解析不一致」时用本 skill。

- 无前置代理（直连源站）→ 走私无从谈起，别测。
- h2c upgrade 走私 → 统一归本 skill。
- 纯 ws:// 端点 → api-rest/websocket skill。

## 一句话说清
前置代理（CDN/WAF/Nginx）和后端对 `Content-Length`/`Transfer-Encoding` 解析不一致 → 半包塞进流，影响下个用户。SRC 价值：成功 desync = P1/P0（$2k–$10k+）。

## 类型速览
| 类型 | 前置代理用 | 后端用 |
|---|---|---|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | 都看，但前后处理混淆 | 同 |
| HTTP/2 → HTTP/1 desync | h2 | h1 后端 |
| CL.0 | CL=0 后端忽略 | 后端读 body |

## 判断流程（★ 核心，任一步 NO 就停）

### Step 1 — 判前端类型（1 个请求）

看响应头 `server` / `via` / `x-cache` / `cf-ray` / `x-served-by` 有无 CDN/WAF/代理指纹：

- 有代理指纹 → 存在走私前提，进 Step 2
- 无（直连源站）→ **走私无从谈起，放弃**

### Step 2 — 三种探测（各发 1 个，判类型）

同一连接分别发 CL.TE / TE.CL / TE.TE 三种包，观察：

- **CL.TE**：前端按 CL 读 body，后端按 chunked → 后端读到多余字节「G」当下一请求前缀 → 下一请求响应错位（以 G 开头 / 404）
- **TE.CL**：后端按 CL 只读部分 → 剩余字节走私；表现 = 超时（后端等剩余 body）
- **TE.TE**：TE 头混淆（大小写/空格/重复）使一端忽略 TE、另一端按 chunked → 触发前后端差异（这是唯一判断点：TE 头混淆触发差异）
- 三种全无异常 → **放弃**（目标两端解析一致）

### Step 3 — 确认标准（防误判）

同连接发 2 个请求，第 2 个响应带「G」前缀 = 确认 CL.TE。必须 **可复现（连发 2-3 次都错位）**，单次偶发不算。

## 证据 / 不要做的事

- 证据 = 同连接 2 请求、第 2 响应带 G 前缀 + 可复现。
- 低速单次验证，别在生产大流量 desync 测试（影响他人请求）。
- 别把走私的恶意响应缓存到全站共享路径（会毒害所有用户）。
- 看到 desync 现象即停，别真偷 cookie/token。
- 代理日志与后端日志请求数对不上、偶尔 503/502 是通用指纹。
- 命中分布（H1 已披露 High/Critical）：HTTP Request Smuggling 27 条 / CRLF Injection 5 / 响应拆分 2，赏金 $750–$20000。
