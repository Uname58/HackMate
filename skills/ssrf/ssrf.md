# SSRF / Host Header / 缓存投毒 — 决策索引

## 一句话说清
- **SSRF**：让服务器替你向"它能到、你不能到"的地方发请求。
- **Host Header 注入**：通过伪造 Host / X-Forwarded-* 让应用错误地构造 URL / 缓存键。
- **缓存投毒**：把恶意响应固化到共享缓存层，让后续用户中招。

SRC 价值：未授权 SSRF→云元数据 → P0 ($3k–$20k)；缓存投毒（管理后台） → P1。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| URL 入参 / 头像抓取 / Webhook / SSO / `url`/`callback`/`return`/`redirect`/`feed`/`image` 等参数让服务端发请求 | `10-ssrf-core.md` |
| 目标是 AWS / GCP / Azure / K8s 元数据 / S3 / IAM 越权 | `11-cloud.md` |
| 反代 / CDN / Varnish / Cloudflare / Fastly / `Cache-Control` / `Vary` 头 / 静态资源缓存命中规则可控 | `12-cache.md` |
| Host header / X-Forwarded-* 注入(影响密码重置链接、CSRF token、cache key) | 看本 00-index §3.9 §5(Host Header 利用链) |