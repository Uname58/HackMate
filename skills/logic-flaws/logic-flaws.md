# Business Logic overview

> 排他：仅当「业务状态机缺陷（支付/券/验证码/密码重置/CSRF/点击劫持）」时用本 skill。IDOR/越权 → idor；并发竞态 → race-conditions；本 skill 只管业务流程篡改与重放。

## 一句话说清
逻辑漏洞 = 程序按预期工作，但预期不对。无固定 payload，靠流程理解 + 篡改 + 重放，WAF 拦不住。

## 判断流程（核心，正文 Step1-5）
支付改 price 看订单总额是否变（变=命中，不变=后端重算停）→ 竞态并发 N 请求查余额（>1 成功=确认）→ 密码重置取 3-5 token 看可预测性 → CSRF 敏感操作无 token/Referer/SameSite=直接 PoC → 篡改字段不采纳/并发只成功 1 次/token 无规律=停。

## 工具
无固定工具；并发用 Burp Turbo Intruder 或 asyncio。
