# File Upload overview

> 排他：仅当「上传点校验绕过 / 上传后解析」时用本 skill。纯 URL 参数读文件 → path-traversal；上传+解析完整 RCE 链 → rce；本 skill 只管上传点校验绕过。

## 一句话说清
文件上传 = 把不可信字节存到服务器 + 后端能解析它。两层都突破：①绕过校验 ②触发解析。成功=直接 RCE(P0)，失败=受限上传(P2/P3)。

## 判断流程（核心，正文 Step1-5）
.jpg 基线成功 → shell.php 正常 Content-Type 被拒=有校验 → 逐层换壳(扩展名/Content-Type/magic bytes)定位校验层 → 上传后访问 URL 判「源码(未解析) vs 执行(uid=)」→ 全不解析=降级测存储 XSS/XXE/phar。

## 工具
run_tool 调 fuxploider（上传点爆破）。
