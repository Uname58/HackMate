# SQL 注入

## 一句话说清
SQLi = 把"数据"提升为"SQL 指令"。
SRC 价值：能拖库或读 admin hash 的 SQLi → P1，DBA 权限或 RCE 升级 → P0。
WooYun 27,732 案例中，**66% 在登录框、64% 在搜索、60% 在 POST 表单、26% 在 HTTP Header**。