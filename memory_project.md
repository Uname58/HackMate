# HackMate 项目交接记录

## 2026-11-02 五 Agent 架构实施进度（首版进行中）

- 用户确认五 Agent 是正式设计基准：Recon → Analyze → Attacker → Reporter → Commander。产品面向机器擅长的多类技术测试；Reflected XSS 是第一个完整切片，后续包含 SQLi、CMDi、信息泄露和 WordPress 组件/CVE，不限定 XSS。
- M0 基线审计、M1 合同草案已记录在 `docs/architecture/` 和 `schemas/`；五类 Agent 输出及共享对象由标准库 Schema 子集校验器验证，合同仍待评审冻结。
- 新代码按职责放入 `hackmate/agents/`、`orchestrator/`、`security/`、`evidence/`、`workflow/`。SQLite 状态机、显式 Scope Gate、EvidenceRepository、CLI `/task` 和 Web 工作台工作流入口已有首版；旧 CLI/Web 对话路径继续保留。
- 当前 Attacker 仅启用 Reflected XSS 工具适配器。其他类型即使 Analyze 提出，也会 BLOCKED，不会借用 XSS 工具误测。增加新类型需新增适配器、Skill、证据规则和 Eval。
- Reporter 按 Attacker 提供的 Evidence ID 独立从仓库读取原件；原件保存在本机，发给 LLM 的提示词副本会尽力脱敏 Cookie、Authorization、token、password 等常见字段。此过滤不是完整隐私保证；文本型 Reporter 不能视觉读取截图。
- CDP 工作流对导航和后续请求做 Scope Gate 检查，证据可保存 CDP 事件、响应体和确认截图；Reporter 独立审查后会保存 Schema 校验的 Finding 与脱敏 Writeup；CLI/Web 共用状态机服务。离线架构/流程 Eval 已写，真实模型、真实浏览器和授权靶场端到端流程尚未验证。
- Attacker 每轮只提交一个工具动作；工具必须同时获当前适配器和 Analyze 测试计划允许，并在预算内依据上轮结果继续。XSS Reporter 要求原始请求与响应关联同一 endpoint 和同一参数值，并检查原始 CDP JavaScript 执行事件。Reporter 要更多证据时可进行有上限的 Analyze/Attacker/Reporter 重试；XSS 验证缓存按任务隔离，不能拿另一任务的缓存当新证据。
- EvidenceRepository 在写入和读取时都会验证 `evidence.schema.json`。原始请求、响应、CDP 事件和执行记录用 Evidence ID 关联；这仍不代表已完成真实目标端到端审查。
- ResearchRepository 和 Web UI 已接通完整候选链：同任务来源证据 → 人工关联同任务原始请求/响应、浏览器、CDP 或工具验证证据 → 现有 regression/hidden Eval → 明确人工批准 → 现有 Skill improver，再经 Skill before/after gate 决定保留或回滚。浏览器 Eval case 逐项过 Scope Gate，Skill 更新需 IMPACT 授权。没有现成 Skill/Eval 目录的漏洞（如当前尚未建立的 WordPress 组件域）暂不能晋升。
- 本轮验证通过：`python -m unittest discover -s tests` 共 48 项；`python -m compileall -q hackmate tests` 通过；`schemas/` 和 `evals/` 下 45 个 JSON 文件可解析；`git diff --check` 无空白错误。这些检查不等于真实模型、浏览器或授权靶场验证。
- Gate 覆盖精确 origin、解码后路径、授权 HTTP 方法、请求配额、DNS 地址变化和 CDP 重定向；非安全方法升级为 IMPACT 并要求逐工具批准。通用 vendor CLI 和 shell 暂时 fail-closed。上述为代码与离线用例证据，不等于真实网络安全验证。
- Gate 配额及 DNS 地址观察状态已修正为任务级共享，并写入 SQLite；跨 Agent 阶段和显式恢复不再重置请求总量或每分钟限额。新增离线回归用例覆盖状态重建及超额阻断。
- 待后续：在授权本地环境做真实流程验证、扩大全量 Agent/回归 Evals、为 SQLi/CMDi/信息泄露/WordPress 建立独立攻击适配器与 Eval。中断且结果未落盘的攻击不会自动重放。

> 面向接手本仓库的其他 coding agent。此文件是人工维护的项目交接上下文，不是 HackMate 的运行时记忆；HackMate 不读取或写入此文件。
> 接手后请先核对当前代码和 `git status`，本记录可能落后于工作区。更新时保留仍有效的事项，并注明已完成或已变化的内容。

## 项目概况

- HackMate 是一个 Python CLI + 本地 Web 工作台红队副驾驶，辅助人工进行授权安全测试；首个五 Agent 闭环关注 reflected XSS，长期范围还包括 SQLi、CMDi、信息泄露和 WordPress 组件/CVE。
- 项目强调人工控制和证据驱动。测试范围、授权和当前状态应以用户指令及实际工具证据为准。
- HackMate 自己的运行时记忆仍在 `memorys/`：长期记忆位于 `memorys/long/`，项目中记忆位于 `memorys/project/current.md`，短期对话在运行期间维护。

## 最近的项目状态

### 2026-11 改动（最新，设计决策已落 DESIGN.md / system_prompt）

- **verify 三机制**（`tools.py` 新增 `VerifyState` 类 + `config.py` 加 `verify_ttl_days`/`verify_max_consecutive_fail`）：verify 判定的阴性对照（baseline test123）、全量落盘（`memorys/verify.jsonl`）、查重 + 连续失败停止。ToolContext 自动创建 verify_state，webui.py/repl.py 两处构造点未改。
- **vendor 新增 wpscan + whatweb**（Docker 运行，不用装 Ruby）：`wpscanteam/wpscan`（WordPress 枚举）+ `azurielus/whatweb`（技术栈指纹），tools.json 现 12 个工具。recon 指令还没接「技术栈识别用 whatweb、WordPress 用 wpscan」——待办。
- **核心定位（人机分工）**：AI 逐步覆盖技术类漏洞（XSS/SQLi/CMDi/Info Disclosure/File Upload/WordPress 组件 CVE），人做逻辑类漏洞（HackMate 帮分析架构）；五 Agent 首个闭环仍是 XSS。
- **能力模型（分析/验证/评估）**：每个漏洞模块按这三段拆。
- **判型方法论（数据流 sink 分析）**：已写进 `memorys/long/system_prompt.md` §7——数据流（拼 SQL→SQLi、渲染→XSS、当路径→LFI、当命令→cmdi 等）判型 + 功能/权限模型 + 通用检查。
- **旧规划已被 2026-11-02 的迁移取代**：五 Agent 合同、职责目录、Orchestrator 和共享证据仓库的首版已存在，具体状态见本文件顶部。

### 早期改动（Web 工作台等，历史）

- 最近新增了本机 Web 工作台：入口/后端会话逻辑在 `hackmate/webui.py`，页面布局、样式和前端交互在 `hackmate/web/index.html`，启动说明在 `README.md`。工作台复用 HackMate 的 LLM 客户端、工具注册表和 CDP 会话；聊天、行动记录和目标树保存在当前进程内。
- 三栏工作台左右栏宽度现固定为左侧 248px、右侧 292px；应用最小宽度为 960px，小于该宽度的视口可横向滚动，中间栏保留至少 420px。
- 左侧站点树采用 ZAP Sites 风格的可折叠 `Sites` 根节点，网站 origin 缩进列在其下；网站和有子项的目录行均可独立展开、收起，支持鼠标和键盘操作。状态在前端按 Sites / origin / path 保存，页面轮询重绘时会保留。若某个路径本身也是页面，点行选择页面，点箭头折叠子目录。
- 每个网站节点行尾的 `×` 会将该网站及其整棵子树从当前左侧显示中移除，不删除后端已观察到的页面数据；标题栏的“恢复网站”按钮可恢复所有移除项。Recon 使用当前显示的网站列表。
- Web 工作台左侧有站点结构和 Recon 按钮。`WebSession.start_recon()` 当前经由 LLM/工具对话路径处理侦察请求；旧的 `_run_recon()` 同源爬取实现带有 Scope Gate 与逐跳重定向检查，但目前没有调用方，不能当作现行执行路径。工作台 Recon 与五 Agent `/task` 流程是两条不同入口。
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
