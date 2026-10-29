# 路径遍历 / LFI

> 视角：黑盒。**判断流程优先，payload 靠现场构造不背。**

## 排他声明
仅当「文件路径入参可控（file/path/page/include），读文件或包含」时用本 skill。
- 上传文件名 / 压缩包穿越（Zip Slip）→ file-upload
- 拿到 webshell / 已 RCE → rce
- 参数走 include/require 且升级到 RCE → 本 skill 判「包含」，拿到执行后转 rce
- 本 skill 只管：读文件 / 包含的探测与判定

## 一句话说清
路径遍历 = 文件路径逃出目录边界。核心判断就一个：这参数是「读文件」还是「包含执行」。

## 判断流程（★ 核心，每步几个请求→什么结果→什么结论→NO 就停）

### Step 1 — 基础探测（1 个请求）
?file=../../etc/passwd：
- 200 + root:x:0:0 内容 → 命中，直接确认，进 Step 3 定「读 vs 包含」
- 404 / 空 / 无差异 → 存在前后缀拼接或过滤，进 Step 2

### Step 2 — 判断拼接形态（2-3 个请求）
- 换绝对路径 /etc/passwd → 成功 = 无前缀拼接，只是遍历深度不够
- 试 ....// 双写（服务端删一次 ../）→ 成功 = 有删除过滤
- 试 %2e%2e%2f / 双重编码 %252e / Unicode %c0%af → 成功 = WAF 级过滤
结论决定下一步：null byte（后缀拼接）/ 绝对路径（前缀拼接）/ 深度枚举（层数不够）。

### Step 3 — 关键区分「读 vs 包含」（1 个请求，决定严重度）
看参数语义：file_get_contents/readfile = 只读；include/require = 会执行 PHP。
- 只读 → 最多拿源码/配置，P1/P2，读完即停
- 包含 → 可升级 RCE（日志投毒 / php://input / data:// / session），确认后转 rce skill

### Step 4 — 读源码（PHP 站必做，1 个请求）
?file=php://filter/convert.base64-encode/resource=config.php → base64 解码即源码。
filter chain 概念：多个 filter 可串联（convert.base64-encode|string.rot13），也能用于 LFI→RCE（iconv 链，属 rce 范畴）。

### Step 5 — 放弃条件
3 种编码 + 绝对路径 + 深度枚举（3-10 层）均无差异 → 不是路径遍历，停。别继续堆 ../ 硬试。

## 工具
无固定工具。读到的源码/配置即证据，保存脱敏。

## 证据 / 不要做的事
- 证据：①基线请求 ②命中请求 + 回显内容（脱敏）③读到的配置/DB 密码截图。
- 只读 /etc/passwd 前 3 行、配置只取关键字段，不拖全文件。
- 读 vs 包含用参数名 + 源码语义判，别猜。
- 包含点升级 RCE 拿到 uid= 即停，不留 shell。
- 遍历深度先 3-10 层，别一开始就百层扫。
