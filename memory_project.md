# HackMate 项目交接记录

> 面向接手本仓库的其他 coding agent。此文件是人工维护的项目交接上下文，不是 HackMate 的运行时记忆；HackMate 不读取或写入此文件。
> 接手后请先核对当前代码和 `git status`，本记录可能落后于工作区。更新时保留仍有效的事项，并注明已完成或已变化的内容。

## 项目概况

- HackMate 是一个 Python 命令行红队副驾驶，目标是辅助人工进行授权安全测试；当前主要关注 reflected XSS。
- 项目强调人工控制和证据驱动。测试范围、授权和当前状态应以用户指令及实际工具证据为准。
- HackMate 自己的运行时记忆仍在 `memorys/`：长期记忆位于 `memorys/long/`，项目中记忆位于 `memorys/project/current.md`，短期对话在运行期间维护。

## 最近的项目状态

- 最近新增了本机 Web 工作台：入口/后端会话逻辑在 `hackmate/webui.py`，页面布局、样式和前端交互在 `hackmate/web/index.html`，启动说明在 `README.md`。工作台复用 HackMate 的 LLM 客户端、工具注册表和 CDP 会话；聊天、行动记录和目标树保存在当前进程内。
- 三栏工作台左右栏宽度现固定为左侧 248px、右侧 292px；应用最小宽度为 960px，小于该宽度的视口可横向滚动，中间栏保留至少 420px。
- 左侧站点树采用 ZAP Sites 风格的可折叠 `Sites` 根节点，网站 origin 缩进列在其下；网站和有子项的目录行均可独立展开、收起，支持鼠标和键盘操作。状态在前端按 Sites / origin / path 保存，页面轮询重绘时会保留。若某个路径本身也是页面，点行选择页面，点箭头折叠子目录。
- 每个网站节点行尾的 `×` 会将该网站及其整棵子树从当前左侧显示中移除，不删除后端已观察到的页面数据；标题栏的“恢复网站”按钮可恢复所有移除项。Recon 使用当前显示的网站列表。
- Web 工作台左侧增加了站点结构排序和 Recon。Recon 的入口是 `WebSession.start_recon()`，同源爬取逻辑在 `_run_recon()`，HTTP 路由是 `POST /api/recon`；前端状态和按钮逻辑在 `hackmate/web/index.html` 的 `renderRecon()` 与 `reconButton` 事件处理器。它读取 HTML 中的 `<a href>`，使用同源 GET 请求，尊重 `robots.txt`，最多检查 300 页、深度 8；不执行 JavaScript，因此不会发现 `window.location.href` 动态路由，也不提交表单或扫描参数。URL 查询部分不显示在结构树中。
- 接手 Web 工作台时无需重写；先看 `README.md`、`hackmate/webui.py`、`hackmate/web/index.html` 和当前 `git status` / diff。后续若继续增加工具或扩大前端功能，可考虑把爬取逻辑、HTTP 会话和静态 CSS/JS 拆分；这只是可选整理，不是当前继续开发的前置条件。
- 修改 Web 工作台代码后需重启已运行的 HackMate 进程，才能加载新的后端路由和会话代码。已有 UI 进程可能仍在运行旧版本。
- 最近这组 Web 工作台 / Recon 变更尚未有自动化或真实浏览器端到端验证；接手时应先检查当前 diff，再按用户需要决定验证范围。
- 本次工作区最近讨论了让浏览器工具复用专用测试标签，避免每个测试步骤都新开页面。相关实现改动涉及 `hackmate/cdp.py`、`hackmate/tools.py`、`hackmate/grader.py`、`hackmate/repl.py`，README 中也有对应说明。
- 曾对改动涉及的 Python 文件做静态语法解析，解析通过；没有进行自动化测试或真实浏览器验证。接手时应先查看当前 diff，再决定是否需要验证。
- 用户曾要求撤销 `/clear` 相关改动；不要仅凭旧对话摘要重新加入这类改动，应以当前代码为准。
- `hackmate/agent_link.py` 是此前新增的 HackMate 与其他 agent 对话尝试入口；其现状和完成度需检查代码确认。

## 当前靶场进度（来自此前对话记录）

- 靶场：XSS-Labs，地址 `http://localhost:8080`；当前方向为 reflected XSS。
- 记录为已确认的关卡：level1、level6、level10、level17、level18。确认依据应以各次浏览器/CDP 证据和项目中的 eval/case 记录为准。
- 最近一次记录：level18。曾观察到 `arg01` / `arg02` 进入 `<embed>` 的无引号属性值区域，特殊字符 `<`、`>`、`"` 被实体编码而空格保留；报告的 hover payload 为 `arg02=BBB onmouseover=alert(1)`。
- 后续曾建议继续 level19/20；开始前应先确认靶场和浏览器当前状态，并按 HackMate 的流程读取相关 XSS skill。

## 接手时的注意事项

- 先运行 `git status --short` 并查看 `git diff`，尤其注意已有未提交修改和新增文件；不要覆盖或清理其他人的工作。
- 本记录不替代代码、测试结果、浏览器观察或用户授权。不要把旧记录当作当前运行状态或已验证结论。
- 若用户要求继续靶场测试，限于用户授权的本地靶场；依据可观察证据报告验证状态，不因 payload 被发送或反射就声称执行成功。
- 对 HackMate 的具体实现，优先查阅 `CLAUDE.md`、`README.md`、`DESIGN.md` 及对应模块；不要从这份交接记录推断尚未验证的行为。
