# Unauth Access overview

> 排他：仅当「完全无凭证 / 默认凭据 / 管理面直接暴露」时用本 skill。带合法低权 token 越权 → idor；本 skill 是「完全无凭证/默认凭据/管理面直暴露」。

## 一句话说清
未授权访问 = 服务该有鉴权但没有。入口最浅影响最重：扫端口 + 一次 curl 即拿数据/RCE。

## 判断流程（核心，正文 Step1-5）
nmap 扫高危端口命中 6379/9200/2375/10250 → 对号入座探针（Redis ping=PONG=未授权 / ES _cat/indices 200=未授权 / Actuator /env 200=泄露）→ 未命中 → ffuf 路径 fuzz 后台/actuator/swagger 200/302=命中 → 高危端口无+路径 fuzz 无=停 → 读类返回数据=确认，写类只做读证明。

## 工具
nmap / ffuf（run_tool 或直接终端）。
