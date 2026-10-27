# REST / GraphQL / WebSocket API 安全 — 决策索引

## 一句话说清
REST API 漏洞 = 把"端点 + JSON 字段"当攻击面。
最常见 4 类：BOLA（IDOR 升级版）、Mass Assignment、速率 / 配额缺失、CORS 配置错。
SRC 价值：BOLA / Mass Assignment 在大厂常见 P1 ($1k–$8k)。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 见到 `/api/v1/.../{id}` REST endpoint / 数值 ID / GUID / `PATCH`/`PUT` body / `X-RateLimit-*` 头 | `10-rest-api.md` |
| 端点是 `/graphql` / `/api/graphql` / 接受 `query`/`mutation`/`__schema` | `11-graphql.md` |
| 端点是 `wss://` / `ws://` / Sec-WebSocket-Protocol | `13-websocket.md` |
| 看到 `Authorization: Bearer eyJ...` (JWT) | 优先去 `../oauth-saml-jwt/12-jwt.md`,本目录 `12-jwt-api.md` 是 API 上下文的补充 |

> 注:`11-graphql.md` 与 `../graphql.md`、`12-jwt-api.md` 与 `../oauth-saml-jwt/12-jwt.md` 有内容重叠——本目录从 API 视角组织,跨参考时按需选一处。