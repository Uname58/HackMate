# 信息泄露 / 敏感文件 / 备份

> 视角：黑盒，主动探测路径 + 被动收集前端线索。判断流程优先，payload 靠现场构造不背。

## 排他声明
仅当目标是「读数据 / 拿配置 / 拿源码」的泄露。泄露凭据拿去横向 → intranet-postexp；反复拉 actuator/heapdump 让资源耗尽 → dos；路径探测打到内网/云元数据 → 先确认 scope 是否覆盖。

## 一句话说清
信息泄露 = 服务暴露了不该暴露的资产。SRC 关注链路终点：.git → 源码 → 数据库密码 = P0。WooYun 7,337 案例 48.7% 敏感信息泄露、40% 涉及凭证/数据库。

## 判断流程（★ 核心）

### Step 1 — 打 3 个最高命中路径（3 个请求）
/.git/HEAD、/.env、/wwwroot.zip 各 1 次请求，判 200 / 403 / 404。
- 200 → Step 3
- 403/404 → Step 2
- 三个全 404 且无前端线索 → 停（不 dump 整字典）

### Step 2 — bypass 矩阵（1-2 次再试）
大小写（/.GIT/、/.GiT/）、URL 编码（%2e）、路径穿越（/x/../.git/）、双斜杠（//.git/）。仍 404 → 停，不无脑换字典 fuzz。

### Step 3 — 200 读响应体判类型
- .git HEAD 内容 `ref: refs/heads/...` → git-dumper 还原
- .env 含 `=`（KEY=VALUE）→ 配置泄露，看密钥类型定影响
- .zip Content-Length > 1MB → 整站源码

### Step 4 — 量化停损线
- 探测请求总数 < 200 条，超出即停
- .git 还原到「看到配置文件名」即止，不全量 clone
- 拿到凭据只验证身份（sts get-caller-identity / telnet 通端口），不连生产库

## 高频路径（每类命中率 Top3，其余现场 Google）
- 版本控制：/.git/HEAD、/.svn/entries（393 例高频）、/.svn/wc.db
- 备份（565 例，命中率最高）：/wwwroot.zip、/www.zip、/{域名}.zip
- 配置：/.env、/config.php.bak、/web.config.bak
- 探针：/phpinfo.php、/server-status、/jolokia/list
- 日志：/ctp.log（致远 OA 高频）、/debug.log、/storage/logs/

## 通用指纹（命中即按类型走利用链）
- `/.git/HEAD` 200 + `ref: refs/heads/main` → 立即 dump
- `/.env` 200 + text/plain + 含 `=` → 配置泄露
- `/wwwroot.rar` Content-Length > 1MB → 整站源码
- `/actuator/health` 200 + `{"status":"UP"}` → 进一步探 actuator/env / heapdump
- `/swagger-ui.html` 渲染出 API 列表 → 全量端点

## 利用链终点（读数据后的价值放大）
- .git → 源码 → grep 凭据 → 数据库密码
- .env → S3/Stripe/SMTP/JWT 凭据 → 接管（只验证身份不操作）
- heapdump → JVM 内存里的密码（strings 过滤）
- Swagger → 隐藏端点 → 全量打（→ 各自 skill）

## 真实案例指纹（精简）
- wooyun-2015-0125565：阡陌金融 .git → 数据库密码
- wooyun-2013-038850：TOM SVN 泄露 → 源码 → SQLi
- wooyun-2015-0128813：零食电商短信 API → 短信 → 账户接管
- H1 Shopify #1087489：GitHub PAT 泄露（$50k，信息泄露类最高）

## 证据 / 不要做的事
- 脱敏：凭据前 2 + 后 2 + 长度，附 sha256 指纹证明拿到过
- 禁：clone 源码传公网；用泄露凭据建资源/发邮件/扣款；连生产库导出数据；给真实手机发短信
- 限：扫描 1–5 rps，探测请求 < 200 条
- CVSS：.git 泄露 7.5 / .env 泄露 prod 凭据 9.8 / phpinfo 5.3 / heapdump 含 DB 密码 9.8
