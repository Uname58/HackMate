# 文件上传(任意写入 / Webshell)— 决策索引

## 一句话说清
文件上传 = 把不可信的字节存到服务器 + 后端能解析它。
两层都得突破：(a) **绕过校验**，(b) **触发解析**。
SRC 价值：成功 = 直接 RCE，P0；失败 = 受限上传，P2/P3。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 普通上传点(form-data file) / 头像 / 图片 / 文档上传 | `10-upload-bypass.md`(扩展名 / MIME / 空字节 / Content-Type 全套) |
| 上传 `.zip`/`.tar`/压缩包 → 服务端解压 / `tar` 命令 | `11-archive-traversal.md`(Zip Slip / 解压路径穿越) |
| 上传后有 "校验 → 移动" / "扫描 → 删除" 流程 / 上传同时直出预览 URL | `12-race-download.md`(竞态 + 任意下载) |
| 直接拼到 webshell:见 `../rce/13-file-rce-chain.md`(上传 + 解析配合) |