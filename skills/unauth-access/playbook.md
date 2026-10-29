# 未授权访问 / 默认凭据

> 视角：黑盒，假定只有 URL。**判断流程优先，payload 靠现场构造不背。**

## 排他声明
仅当「完全无凭证 / 默认凭据 / 管理面直接暴露」时用本 skill。
- 带合法低权 token 越权 / 改 ID 读他人资源 → idor
- 本 skill 是：完全无凭证、默认凭据、管理面直暴露的判定

## 一句话说清
未授权访问 = 服务该有鉴权但没有。WooYun 88,636 漏洞中 16.2% 是未授权——最容易开胡。

## 判断流程（★ 核心，每步几个请求→什么结果→什么结论→NO 就停）

### Step 1 — 高危端口扫描（1 个 nmap）
nmap -sV -p 6379,9200,2375,2379,10250,8080,3306,27017,11211,2181,873,8088,7001 target
命中高危端口 → 对号入座进 Step 2；全部关闭 → 进 Step 3 路径 fuzz。

### Step 2 — 探针 = 结论（每个服务 1 个请求）
- Redis 6379：redis-cli -h IP ping → PONG = 未授权（确认，只读 info，不写）
- Elasticsearch 9200：curl IP:9200/_cat/indices → 200+索引列表 = 未授权
- Docker 2375：curl IP:2375/containers/json → 200 = 未授权（容器逃逸风险）
- Kubelet 10250：curl -k https://IP:10250/pods → 200 = 集群接管风险
- Spring Actuator：curl /actuator/env → 200 = 泄露（可 heapdump 拿 DB 密码）
- Etcd 2379 / ZooKeeper 2181 / rsync 873 / MongoDB 27017 / Memcached 11211：各自 1 行探针，返回数据 = 未授权
- 无响应 / 401 / 403 → 换下一个服务

### Step 3 — 路径 fuzz（命中端口但无已知服务，或 80/8080 开放）
ffuf -u http://target/FUZZ -w admin-paths.txt -mc 200,302,401
命中后台 /actuator /swagger /phpmyadmin → 200/302 = 命中，进 Step 5 确认
关键 path：admin/ manager/html jmx-console/ web-console/ console/ phpmyadmin/ actuator/env swagger-ui.html .env debug/

### Step 4 — 停止条件
高危端口无 + 路径 fuzz 无 200/302 → 放弃，停。别继续扩大扫描面（禁扫 /16 以上网段）。

### Step 5 — 确认与取证（读类 vs 写类）
- 读类（ES 索引 / Actuator env / 数据导出）：返回数据 = 确认，取 1-3 条脱敏即停
- 写类（Redis 写马 / WAR 部署 / OUTFILE）：只做读证明（ping/info/版本），绝不写文件、不留后门、不 cron

## 工具
nmap、ffuf（限速 1-5 rps）。默认凭据表 / hydra 爆破见附录（压成一行）。

## 附录（默认凭据 + 爆破，仅查不背）
默认凭据：Tomcat tomcat/tomcat、WebLogic weblogic/weblogic1、JBoss admin/admin、Jenkins admin/admin、Grafana admin/admin、phpMyAdmin root/、海康 admin/12345、大华 admin/admin。hydra 爆破：hydra -L u.txt -P p.txt -t 4 target http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"，限 50 次/小时，别无脑爆破。

## 证据 / 不要做的事
- 证据：①nmap 端口开放截图 ②探针请求+响应（200+数据）③数据样本（脱敏）。
- 禁：Redis/Mongo 写马、留 webshell、上 cron——只做读类证明，需写文件时用 poc-日期.txt 并立即清理。
- 禁：从 Mongo/ES 拖超 10 条记录，取 1-3 条脱敏。
- 禁：默认凭据登录后创建/删除数据，证明可登录即退出。
- 报告脱敏：内网 IP、域名、手机号、邮箱、token；敏感值用 ****** 替 4 字符以上串。
- 限速：path fuzz 1-5 rps 单机不并发。
