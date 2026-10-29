# RCE overview

> 排他：仅当目标是「服务器执行任意命令/代码」时用本 skill。xxe（文件读/SSRF）→独立；文件上传/包含→file-upload/path-traversal；堆叠 xp_cmdshell→sqli（只证明注入）；模板表达式→本 skill 的 ssti。

## 一句话说清
RCE = 在目标服务器上执行任意命令。所有漏洞类型里价值最高，未授权 RCE 通常 $5k–$50k+。两条路：(a) 命令注入（拼接系统命令）；(b) 反序列化 / 表达式注入（运行时 evaluate）。

## 判断流程（核心，正文 Step1-3）
入口分类（拼接命令/模板表达式/反序列化/上传解析，先指纹：报错/框架特征/Cookie rO0AB）→ 确认标准（命令注入必须 OOB 或 sleep5vs0 ≥3 次；SSTI 先 {{7*7}} 确认求值；反序列化先无害 dnslog）→ 停损（whoami/id 证明执行即停，不上 shell 不落地 webshell；5 种外带通道全失败→放弃）。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 用户输入拼接进系统命令 / ping、nslookup、文件解压转换功能 | `command-injection.md` |
| Cookie/ViewState 含 `rO0AB`(Java) 或 `O:` 开头(PHP) / pickle / yaml.load / Marshal.load | `deserialization.md` |
| 模板表达式 `{{7*7}}` / `${7*7}` / `#{7*7}` / `%{7*7}` 被求值 | `ssti.md` |
| Node.js JSON merge / `Object.assign` / lodash `_.merge` 用户输入 | `prototype-pollution.md` |
| 上传点 + 解析配合 / LFI/RFI / 日志投毒 | → file-upload / path-traversal（非本 skill） |

## 工具
检测到命令注入 → run_tool 调 commix（tool="commix", args="-u URL --batch"）。
