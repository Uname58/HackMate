# Path Traversal / LFI overview

> 排他：仅当「文件路径入参可控（file/path/page/include），读文件或包含」时用本 skill。上传文件名/压缩包穿越 → file-upload；拿到 webshell → rce；纯 URL 参数/包含点读文件 → 本 skill。

## 一句话说清
路径遍历 = 用户控制的文件路径逃出应用目录边界。?file=../../etc/passwd 能读=P1，读到配置→DB 密码=P0。

## 判断流程（核心，正文 Step1-5）
?file=../../etc/passwd：200+内容=命中；404/空=有前后缀拼接换绝对路径/....// → 判断拼接形态定 null byte/绝对路径/深度枚举 → 区分「读 vs 包含」（include 会执行 PHP→可升级 RCE）→ 3 种编码+绝对路径+深度枚举无差异=停。

## 工具
无固定工具；PHP 站读源码优先 php://filter/convert.base64-encode。
