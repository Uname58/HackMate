# Info Disclosure overview

> 排他：仅当目标是「读数据 / 拿配置 / 拿源码」这类泄露时用本 skill。泄露凭据被拿去横向 → intranet-postexp；目的是让资源耗尽而非读数据（actuator/heapdump 反复拉）→ dos；路径探测进内网/云元数据 → 先确认是否越 SRC scope。

## 一句话说清
信息泄露 = 服务暴露了不该暴露的资产（源码/配置/密钥/凭据）。SRC 关注链路终点：一个 .git 泄露能直读数据库密码 → P0。WooYun 7,337 案例 48.7% 是敏感信息泄露，40% 涉及凭证/数据库。

## 判断流程（核心，正文 Step1-4）
Step1 打 3 个最高命中路径（/.git/HEAD、/.env、/wwwroot.zip）各 1 次请求判 200/403/404 → Step2 403/404 走 bypass 矩阵（大小写/编码）再试 1-2 次，仍 404 停 → Step3 200 读响应体判类型（.git HEAD ref:→git-dumper；.env 含=→配置；.zip>1MB→源码）→ Step4 量化停损线（探测总请求 <200 条，.git 还原到看到配置文件名即止不全量 clone）。

## 工具
git-dumper / nuclei exposures 模板 / dirsearch（敏感字典）；run_tool 调 git-dumper 还原 .git。
