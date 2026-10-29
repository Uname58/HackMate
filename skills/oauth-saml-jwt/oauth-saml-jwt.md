# OAuth / SAML / JWT overview

> 排他：仅当目标是认证协议 / token（OAuth redirect_uri、SAML Response、eyJ 三段 token）时用本 skill。SQL 注入绕登录 → sqli；XXE → rce；无 OAuth 上下文的纯开放重定向 → ssrf。eyJ 三段 token 是本类唯一强信号。

## 一句话说清
OAuth / OIDC / SAML 把认证外包给 IdP；JWT 是常用 token 格式。能伪造任意身份 = P0；能让回调把 code 发到攻击者域 = P0。

## 判断流程（核心，正文 Step1-3）
JWT 先解码看 alg/kid → HS256 试弱密钥；RS256 且有 jwks 端点才试混淆，无 jwks=NO 停；kid/jku 只在服务端信任 header 内 kid 才试。OAuth 发几请求判 redirect_uri 精确/前缀/无校验。SAML 先删签名重发 ACS，200 登录成功=SP 不验签，401=停。

## 子文件路由
| 入口信号 | MUST Read |
|---|---|
| `redirect_uri` / `client_id` / `state` / `authorization_code` | `oauth-redirect.md` |
| `<saml:Response>` / `SAMLResponse` / SSO Federation | `saml.md` |
| `eyJ` 三段 token / `Authorization: Bearer` | `jwt.md` |
| 登录 / 注册 / 密码重置 / 2FA / 记住我 | `auth-misc.md` |

## 工具
JWT 解码/弱密钥试 jwt_tool；SAML 篡改用 SAML Raider（Burp 插件）。
