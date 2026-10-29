# SSRF overview

> 排他：仅当目标是「服务端主动向攻击者指定的 URL 发请求」时用本 skill。file:// 读文件→path-traversal；XML 实体→xxe；Location 反射→开放重定向；Host 头→缓存投毒。

## 一句话说清
SSRF = 让服务器替你向「它能到、你不能到」的地方发请求。拿到云元数据凭证 = P0（$3k–$20k）。

## 判断流程（核心，正文 Step1-5）
出网判定（先打 OOB/interactsh 确认能连外网，连不通→只能盲 SSRF 或放弃）→ 回显模式（有回显 vs 无回显）→ 端口扫描（时间/长度差，三私网段无差异→停内网探测）→ 协议降级链 http→https→file→dict→gopher → 停损（拿到云元数据凭证即停）。

## 工具
无固定工具；OOB 用自架 interactsh（别用公共 DNSLog）。内网 DB 可利用时 → run_tool 调 sqlmap/gopherus。
