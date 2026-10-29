# REST API overview

> 排他：仅当目标是 REST API 端点（`/api/v1/.../{id}`、JSON body、`PATCH`/`PUT`、`X-RateLimit-*` 头）时用本 skill。eyJ 三段 token → oauth-saml-jwt；`/graphql` 端点 → graphql；纯 IDOR 改 ID 访问他人资源 → idor。本 skill 只处理 REST 专属的 BOLA / Mass Assignment / 速率限制 / CORS。

## 一句话说清
REST API 漏洞 = 把"端点 + JSON 字段"当攻击面。最常见 4 类：BOLA（对象级越权）、Mass Assignment（批量赋值）、速率/配额缺失、CORS 配置错。BOLA / Mass Assignment 大厂常见 P1（$1k–$8k）。

## 判断流程（核心，正文 Step1-4）
BOLA（账号 A 建资源拿 ID → 账号 B GET 该 ID → 200 返回 A 的数据才算确认，403/404=NO 停）→ Mass Assignment（先 POST 正常字段看响应是否回显 role/isAdmin，回显才注入，对比"字段生效 vs 200 没生效"）→ 速率限制（先串行 N 次确认 429，再测绕过头稳定 200）→ CORS（发 `Origin: evil.com` 看 ACAO 头是否回显 + Credentials）。

## 子文件路由
| 入口信号 | MUST Read |
|---|---|
| `/api/.../{id}`、数值 ID、`PATCH`/`PUT` body、`X-RateLimit-*` | `rest-api.md` |
| `wss://` / `ws://` / `Sec-WebSocket-Protocol` | `websocket.md` |
| `eyJ` 三段 token | `../oauth-saml-jwt/jwt.md` |
| `/graphql` / `/api/graphql` 端点 | `../graphql/graphql.md` |

## 工具
双账号对比靠 curl / Burp Repeater；BOLA 枚举用 Burp Intruder；无专门 CLI 工具。
