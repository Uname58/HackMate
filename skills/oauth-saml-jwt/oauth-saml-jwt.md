# OAuth / OIDC / SAML / JWT — 决策索引

## 一句话说清
OAuth/OIDC/SAML 是把"认证"外包给第三方 IdP；JWT 是常用的 token 格式。
SRC 价值：能伪造任意用户身份 = P0；能让回调把 code 发到攻击者域 = P0。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 见到 `redirect_uri` / `client_id` / `state` / `authorization_code` / OAuth 端点 / 开放重定向参数(`url`/`next`/`return`) | `10-oauth-redirect.md` |
| 见到 `<saml:Response>` / `<saml:Assertion>` / `SAMLRequest` / `SAMLResponse` / SSO Federation | `11-saml.md` |
| 见到 `eyJ` 开头三段式 token / `Authorization: Bearer` / `kid` / `jku` / `x5u` / `alg=` | `12-jwt.md` |
| 登录 / 注册 / 密码重置 / 2FA / 验证码 / "记住我" / 会话 cookie | `13-auth-misc.md` |