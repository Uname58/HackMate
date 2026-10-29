# XSS overview

> 排他：仅当「反射/存储/DOM 落点在 HTML/JS 上下文、且可执行 JS」时用本 skill。反射落模板表达式→ssti；Location/redirect 反射→开放重定向；HTML 注入但无法执行 JS→单独归类；反射落 XML/JSON 解析→xxe/jsonp。

## 一句话说清
XSS = 注入恶意 JS，在受害者浏览器、目标源内执行。验证 = 真实浏览器 alert 弹出（console 无解析错），不是 payload 出现在源码里。

## 判断流程（核心，正文 Step1-4）
三态判定（只报「可执行」态，raw/encoded 不算，连续 5 个 breakout payload 不执行→WAF/编码死锁，放弃）→ CSP 预判（先读 CSP 头，无 unsafe-inline 且无 JSONP→降级 HTML 注入/无脚本）→ 确认阈值（真实浏览器 alert + console 无解析错才算）→ 时间盒（单参数 10 分钟未确认→换下一个）。

## 三大类
- **Reflected（反射型）**：输入立即回显，payload 只在携带它的请求里触发。
- **Stored（存储型）**：输入存进服务端，每次访问都回显，持久，危害最大。
- **DOM-based**：不经过服务端，客户端 JS 把不可信数据写进危险 sink（innerHTML/document.write/eval）。

## 工具
检测到 XSS → run_tool 调 dalfox（扫描）/ blindx（盲 XSS 验证）。
