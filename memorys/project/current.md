目标：PortSwigger 靶场 Reflected/Stored XSS。
已解：
1) Reflected XSS into attribute（双引号属性值 + 角度括号编码）→ `" autofocus onfocus="alert(1)" x="`（search 参数）。
2) Stored XSS into anchor href（双引号 HTML 编码）→ `javascript:alert(1)`（评论 website 字段 → /post/comment，回显 `<a id="author" href="...">name</a>`）。
已 save_case（hidden 集 11 个）。
skill 回灌记录：
- improve_skill(xss, reflection_xss)：29%→14%，已回滚（原文已详实，改动冗余/过拟合）。
- improve_skill(xss, stored_xss)：21%→29%，已保留（原文是 TODO 空壳，补全为完整知识文件，已核实落盘）。
经验：skill 改进价值取决于「原文缺什么」，而非「手上有哪些经验」。
上下文规律（待更多样本验证）：
- href/URL 属性且引号被编码 → 走 `javascript:` 伪协议（需点击，verify_xss 会 INCONCLUSIVE）。
- 属性值可 breakout → 走 autofocus/onfocus（加载即触发，verify_xss 可捕获）；以靶场 Solved 横幅为准。
下一步：继续下一个 PortSwigger 靶场。