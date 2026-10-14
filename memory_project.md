# HackMate 项目交接记录

> 面向接手本仓库的其他 coding agent。此文件是人工维护的项目交接上下文，不是 HackMate 的运行时记忆；HackMate 不读取或写入此文件。
> 接手后请先核对当前代码和 `git status`，本记录可能落后于工作区。更新时保留仍有效的事项，并注明已完成或已变化的内容。

## 项目概况

- HackMate 是一个 Python 命令行红队副驾驶，目标是辅助人工进行授权安全测试；当前主要关注 reflected XSS。
- 项目强调人工控制和证据驱动。测试范围、授权和当前状态应以用户指令及实际工具证据为准。
- HackMate 自己的运行时记忆仍在 `memorys/`：长期记忆位于 `memorys/long/`，项目中记忆位于 `memorys/project/current.md`，短期对话在运行期间维护。

## 最近的项目状态

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
