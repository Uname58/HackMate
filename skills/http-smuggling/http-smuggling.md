# HTTP Request Smuggling overview

> 排他：仅当目标是「存在前置代理/CDN/WAF + 后端，且两者对 CL/TE 解析不一致」时用本 skill。无前置代理→走私无从谈起；h2c upgrade 走私统一归属本 skill；纯 ws:// 端点→api-rest/websocket。

## 一句话说清
前置代理和后端对 Content-Length / Transfer-Encoding 解析不一致 → 攻击者把「半包」塞进流，影响下个用户的请求/响应。成功的 desync = P1/P0（$2k–$10k+）。

## 判断流程（核心，正文 Step1-3）
判前端类型（看响应头 server/via 有无 CDN/WAF/代理指纹，无前置代理→放弃）→ 三种探测（CL.TE/TE.CL/TE.TE 各发一个，超时/503/响应错位分别对应什么）→ 确认标准（同连接 2 请求、第 2 个响应带 G 前缀=确认 CL.TE，需可复现）。

## 工具
Burp HTTP Request Smuggler 扩展 / smuggler.py / h2csmuggler。
