# HTTP Request Smuggling / HTTP/2 Desync

## 一句话说清
前置代理（CDN / WAF / Nginx）和后端服务器对 `Content-Length` / `Transfer-Encoding` 解析不一致 →
攻击者把"半包"塞进流，影响下个用户的请求/响应。
SRC 价值：成功的 desync = P1/P0（$2k–$10k+）。