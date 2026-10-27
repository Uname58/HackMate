# 路径遍历 / LFI / RFI — 决策索引

## 一句话说清
路径遍历 = 用户控制的文件路径绕过应用的"目录边界"。
最经典：`?file=../../etc/passwd`。
SRC 价值：能读 = P1，读到配置 → DB 密码 → P0；任意文件删 = P0（**易遗漏**）。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 文件路径入参(`file`/`path`/`filename`/`page`/`include`)/ 任意文件读 / 任意文件删 | `10-traversal-lfi.md` |
| 参数被当作 URL 拉(allow_url_include)/ 远程脚本拉入执行 / 日志投毒触发 | `11-rfi-logpoison.md` |
| 目标是 PHP 站(`.php` / X-Powered-By: PHP),探伪协议 / Filter / Data / Zip | `12-php-wrappers.md` |
| 探到包含点,链上 Phar / Session / Proc 等高级利用 | `13-phar-session-proc.md` |

> 与上传场景的路径穿越见 [`../file-upload/11-archive-traversal.md`](../file-upload/11-archive-traversal.md)。