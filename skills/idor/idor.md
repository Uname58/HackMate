# IDOR / 任意 X overview

> 排他：仅当「用合法低权身份执行高权操作 / 访问他人资源」时用本 skill。维度内改 ID 读他人资源 → logic-flaws 的 IDOR；完全无凭证 → unauth-access；纯竞态 → race-conditions。

## 一句话说清
越权 = 请求本身合法（带 token、走正常接口），但服务端没校验「这个身份有没有权限做这件事」。任意账号≈RCE，任意操作≈全站管理员。

## 判断流程（核心，正文 Step1-5）
双账号+三角色测序 → 200+数据=疑似漏鉴权、401/403=有鉴权 → 篡改身份字段(sign/password 置空/null/全0/删除)看是否接管 → 拿到 victim token 且 /api/me 返回 victim 资料=确认立即停 → 任意操作：接口 200 且返回 success/状态翻转=确认停。

## 工具
无固定工具；接口发现靠 JS 拆包 / Swagger / 抓包（详见 playbook）。
