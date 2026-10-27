# 业务逻辑 / 越权 / 验证码 / 支付 / CSRF / 点击劫持 — 决策索引

## 一句话说清
逻辑漏洞 = 程序按预期工作，但**预期不对**。
不是注入、不是 RCE，没有"特定 payload"，靠的是**流程理解 + 篡改 + 重放**。
SRC 价值：**很难被 WAF 检测**，公司大厂常因业务复杂而暴露。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 表单 POST 无 CSRF token / Cookie SameSite 缺失 / `Origin`/`Referer` 校验弱 | `10-csrf.md` |
| 用户态 ID 可遍历 / 支付金额可改 / 密码重置流程多步骤 / 验证码可重放 / 优惠券双花 / 余额 | `11-business-logic.md` |
| 敏感操作页可被 iframe 嵌套 / `X-Frame-Options` 缺失 | `12-clickjacking.md` |