【项目收尾】目标：黑盒 XSS 靶场 http://localhost:8080/ （xss-labs 风格，共 20 关，level21=404）。
通过条件：弹窗（靶场把 window.alert 重写为 confirm + 跳转下一关）。
工作流规则：优先自动触发；确认无免交互路径时才请用户人工触发；不自行代点、不用旁证冒充实证。
【已 Solved（12 关）】level 1-10、13、15、16（8/9 为 href javascript: 点击型，经用户人工点击确认；其余 verify_xss CONFIRMED）。解法均已 save_case 进 hidden 集。
【未解（8 关）——收尾结论，均已实测】
- L11 需 raw Referer 头；浏览器侧不可行（URL 规范化、forbidden header、服务端不解码）；用户决定跳过。
- L12 需 raw User-Agent；forbidden header，需 DevTools 设备工具栏/ModHeader/Burp；用户决定不补。
- L14 无注入点（keyword 不反射，静态 iframe+跳转链接）→ 过渡关，本身无漏洞。
- L17/L18：src 未加引号可注入 onmouseover，但仅能鼠标悬停触发；无自动触发路径（onload/onerror 不触发、click 工具不产生 mouseover）。待人工悬停（本次未做）。
- L19/L20：src 带引号，args 在引号内无 HTML 注入点；只剩 SWF(Flash XSS) 路径，Chrome 155 无 Flash → 不可解。
【经验沉淀】skill（reflection_xss/dom_xss）本轮 improve_skill 三次 eval 均回滚（7%→0%、14%→0%、29%→14%），新经验暂存项目记忆：headless 下 autofocus 不触发（用 type=image src=x onerror 代替）；`/` 不分隔未引号属性值；Cookie 可借同源 JS(document.cookie) 自动注入、但服务端 Set-Cookie 重置需写后立即验证；ng-include 可经 class 注入并借同源反射页作模板载体。
项目结束。