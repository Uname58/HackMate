# 远程代码执行 (RCE) — 决策索引

## 一句话说清
RCE = 在目标服务器上执行任意命令。
SRC 价值:**所有漏洞类型中最高**,未授权 RCE 通常 $5k–$50k+。
两条路:(a) 命令注入(拼接系统命令);(b) 反序列化 / 表达式注入(运行时 evaluate)。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 响应/URL 含框架指纹(Log4j/Spring/Fastjson/Struts2/WebLogic/ThinkPHP/Laravel/Shiro/JBoss/Tomcat/Django/Flask) | `10-framework.md` |
| 网络诊断(ping/nslookup) / 文件功能(解压/转换) / 用户输入拼接进系统命令 | `11-command-injection.md` |
| Cookie/ViewState 含 `rO0AB` 二进制(Java) 或 `O:` 开头(PHP) / pickle / yaml.load / Marshal.load | `12-deserialization.md` |
| 上传点 + 解析配合(Apache 多后缀 / Nginx fix_pathinfo) / LFI/RFI / 日志投毒 / 图片马 / .htaccess | `13-file-rce-chain.md` |
| 模板表达式 `{{7*7}}` / `${7*7}` / `#{7*7}` / `%{7*7}` 被求值 | `14-ssti.md` |
| XML 解析点 / SOAP / SVG / DOCX/XLSX 上传 | `15-xxe.md` |
| 自定义依赖 / 私有 npm registry / CI/CD 配置 | `16-supply-chain.md` |
| Node.js JSON merge / `Object.assign` / lodash `_.merge` 用户输入 | `17-prototype-pollution.md` |