# Caution — 坑 / 预警

> 记「别踩什么」。与 skill.md（记「怎么做」）互补，别互相抄。

## 反射型 XSS 常见坑
- `htmlspecialchars` 没加 `ENT_QUOTES` → 单引号没转义，属性内单引号 breakout 仍可打。
- `str_replace` 大小写敏感（漏 `strtolower`）→ 大小写混淆绕过。
- `str_replace` 替换成空（而非占位符）→ 双写 / 嵌套关键字绕过。
- header 值（Referer / User-Agent / Cookie）回显没消毒 → 头注入。
- 属性上下文 vs 文本节点上下文：转义需求不同，别用同一套 payload 硬套。

## 测试方法论坑
- 别只测 GET 参数，POST 参数、header、hidden field 一样可能是反射点。
- 探针要用唯一标记（如 `xssTEST123`），否则反射点多时分不清哪个对应哪个。
- 判断 XSS 成立要「真执行」，不是「payload 出现在源码里」——**alert 弹了才算**。
