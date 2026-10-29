# 文件上传校验绕过

> 视角：黑盒。**判断流程优先，payload 靠现场构造不背。**

## 排他声明
仅当「上传点校验绕过 / 上传后解析」时用本 skill。
- 纯 URL 参数读文件 / 包含点 → path-traversal
- 上传 + 解析完整 RCE 链（拿到 webshell 后提权）→ rce
- 压缩包解压路径穿越（Zip Slip）→ path-traversal / rce
- 本 skill 只管：上传点的扩展名/MIME/magic bytes 校验绕过 + 解析判定

## 一句话说清
上传 = 过校验 + 被解析。校验层只有三种（扩展名 / MIME / 文件头），逐层换壳定位；解析靠访问 URL 判「源码 vs 执行」。

## 判断流程（★ 核心，每步几个请求→什么结果→什么结论→NO 就停）

### Step 1 — 基线（1 个请求）
上传正常 .jpg（type=image/jpeg）→ 200/成功。失败说明上传点本身不可用，停。

### Step 2 — 直传 shell（1 个请求）
上传 shell.php，Content-Type 用正常 application/x-php。
- 被拒 → 有校验，进 Step 3
- 直接成功 → 无校验，进 Step 4 判解析

### Step 3 — 逐层换壳定位校验层（3-4 个请求，对照测试法）
改一个变量（扩展名 / Content-Type / 文件头）看结果差异，即可定位检查点：

| 变体 | 结果 | 结论 |
|---|---|---|
| shell.jpg + Content-Type:image/jpeg 包 php 内容 | 成功 | 只查 MIME |
| GIF89a 头 + php 内容（shell.gif） | 成功 | 只查 magic bytes |
| shell.php.jpg / shell.pHp / shell.php%20 | 成功 | 只查扩展名黑名单（双后缀/大小写/空格绕过）|
| 全部变体仍被拒 | — | 白名单+内容双重校验，进 Step 5 放弃 |

### Step 4 — 解析判定（1-2 个请求）
上传成功后访问返回的 URL：
- 返回 PHP 源码（<?php 可见）→ 未解析，换扩展名/路径（.phtml/.php5/Nginx 路径解析 /uploads/shell.jpg/.php）
- 返回执行结果（?cmd=id 输出 uid=）→ RCE 确认，立即停
- 404 → 换常见解析路径（/uploads/ /upload/ /static/uploads/ /files/）

### Step 5 — 放弃条件
所有变体 + 常见解析路径试完仍不解析 → 不是本 skill 的菜，降级 P2/P3 改测：存储 XSS（.svg/.html）、XXE（.docx/.xlsx/.svg）、phar 反序列化（配合 php://filter 包含点）。别硬试教科书 payload 浪费时间。

## 工具
run_tool 调 fuxploider（-u URL 自动爆破上传点）。

## 证据 / 不要做的事
- 证据三要素：①基线 .jpg 成功 ②定位到的校验层（哪个变体绕过）③执行证明（uid= / 源码回显截图）。
- 只传「echo 标记」测试马（<?php echo "sec_check"; ?>），不传真实 webshell。
- 判定「源码 vs 执行」用返回内容看，别猜。
- 拿到执行后停，不传提权马、不留后门。
- 已传文件无法删除时主动联系厂方清理。
