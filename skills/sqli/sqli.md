# SQLi overview

> 排他：仅当目标是「SQL 语句字符串拼接」时用本 skill。NoSQL / SSRF 打内网 DB / LDAP / XML / 命令注入 → 各自 skill。

## 一句话说清
SQLi = 把"数据"提升为"SQL 指令"。能拖库或读 admin hash → P1，DBA 或 RCE → P0。

## 判断流程（核心，正文 Step1-5）
闭合探测（`'` `"` `)` + AND 1=1/1=2）→ 四分支：报错/布尔/时间/无差异 → 无差异=放弃该参数（NO 就停）→ 按回显能力选技术 → `sleep(5)`vs`sleep(0)` ≥3 次稳定才算确认 → 拿到 `version()+database()` 即停。

## 工具
检测到 SQLi → run_tool 调 sqlmap（tool="sqlmap", args="-u URL --batch"）。
