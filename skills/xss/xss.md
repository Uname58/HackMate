# XSS — Overview

## 是什么
跨站脚本（Cross-Site Scripting）：攻击者注入恶意 JS，在受害者浏览器里、目标站点的源内执行。

## 三大类
- **Reflected（反射型）**：输入立即回显在响应里，payload 只在携带它的请求里触发，非持久。
- **Stored（存储型）**：输入存进服务端（DB/日志/评论），每次访问都被回显，持久，危害最大。
- **DOM-based**：不经过服务端，客户端 JS 把不可信数据写进危险 sink（`innerHTML` / `document.write` / `eval` 等）。

## 通用测试框架
1. 枚举输入点（参数 / 表单 / header / hidden field）
2. 注入探针（特殊字符 + 唯一标记），读响应确认反射点在哪、怎么被处理
3. 分析反射上下文（标签间 / 属性内 / JS 内 / 事件处理器内）
4. 按上下文构造 breakout payload
5. 验证执行（浏览器真跑，alert 弹了才算成立）

## 跨类型通用绕过（三类都适用）
- HTML 实体编码 / URL 编码 / Unicode 编码
- 大小写混淆（`<ScRiPt>`）
- 双写 / 嵌套关键字绕过（`scr<script>ipt`）
- 换行 / 注释混淆（`/**/`、`%0a`）
- 标签替换（`<script>` 被过滤 → `<img onerror>` / `<svg onload>` / `<iframe>`）

## 反射上下文决定 payload 方向（关键）
- 文本节点：`<script>` 直接
- 属性值内（双引号）：`" onmouseover=alert(1)`
- 属性值内（单引号）：`' onclick='alert(1)`
- JS 代码内：`</script><script>` 或 `'-alert(1)-'`
- 事件处理器内：直接 `alert(1)`
