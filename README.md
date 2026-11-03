# HackMate v4

AI 渗透测试副驾驶（human-in-the-loop）。人类主导，AI 辅助侦察 / 分析 / 验证。多漏洞类型（XSS / SQLi / RCE / 文件上传 / 文件包含 / CSRF / 逻辑漏洞 …），按需加载知识 + 工具编排。

两条产品线：
- **CLI**（`chat.py`）—— 对话式打靶。
- **Web 工作台**（`chat.py web`）—— 本地 GUI，复用同一套对话与工具核心。

## 后续架构基准：五 Agent

五 Agent 是后续开发的正式目标架构，采用 **Contract-first → Orchestrator → Reflected XSS Vertical Slice → Evaluation → 扩展**。最终职责为 Recon（事实侦察）、Analyze（假设与计划）、Attacker（按计划执行并留证）、Reporter（独立审查原始证据）、Commander（唯一面向用户并管理任务）。Python Orchestrator 控制状态和阶段交接；Agent 之间使用版本化 JSON Schema，不以自由聊天串联，也不要求五个独立 LLM。

新架构基础设施已形成首版：SQLite 状态机、显式 Scope Gate、证据仓库、JSON Schema 子集校验、CLI `/task` 与 Web 工作台入口。同一任务的请求配额和 DNS 观察状态会跨 Agent 阶段及恢复保留。当前 Attacker 只启用 Reflected XSS 适配器；Reporter 会独立读取原始证据，只有证据充分、能复现且完成误报检查才接受，并保存结构化 Finding 和脱敏 Writeup。Web 工作台的 Research 可按需查 NVD、保存候选、关联人工验证证据、运行已有 regression/hidden Eval、人工批准，再调用 Skill improver；Skill 文件仍须通过现有 Eval gate，且更新操作需要 IMPACT 授权。离线 Evals 已覆盖基本流程、报告生成、Research 晋升和恢复规则；另用临时本机反射页面、真实 Chrome/CDP 和 Fake role client 完成了隔离端到端验证。真实模型和用户指定授权靶场仍未验证。架构面向多种机器擅长的技术测试：后续将逐步加入 SQLi、CMDi、信息泄露和 WordPress crack-in（授权的核心、插件、主题等组件/CVE 验证，不含密码爆破），不把产品限定为 XSS。详细职责、状态、合同和边界见 [`docs/architecture/`](docs/architecture/) 与 [`schemas/`](schemas/)。

Attacker 每轮只执行一个由 Analyze 计划和漏洞适配器共同允许的工具动作，并保存对应原始证据。Reporter 会核对原始请求、响应、输入参数和 CDP 执行事件；证据不足时，Commander 可按任务预算有限重试。增加 SQLi、CMDi、信息泄露或 WordPress 组件验证时，每类都要补独立适配器、Skill、证据判定和 Eval。WordPress crack-in 在本项目中指授权范围内验证核心、插件、主题等组件漏洞，不包含密码爆破。

新增架构代码按职责归入 `hackmate/agents/`、`orchestrator/`、`security/`、`evidence/`、`workflow/`；共享 JSON Schema 保留在根目录 `schemas/`。旧版 `memorys/`、`skills/`、`tools/`、`evals/` 继续保留原有职责，未做大规模搬迁。工作流 CDP 请求会经过权限检查并保存事件、响应体及成功验证截图；脱敏只作用于发给模型的副本，原始证据仍在本机以原件形式保存。

核心卖点是「自主变强闭环」：打靶 → 沉淀 case → 带 eval gate 改 skill → 涨保留 / 跌回滚。

> 版本线：v1 初版 · v2 从 0 重写解决闭环「跑不动」的两个根本问题（见 `DESIGN.md`）· v3 新增本地 Web 工作台 · v4 扩多漏洞类型 + 按需加载 + 工具编排（见 `DESIGN.md`）。

## 快速开始

```bash
pip install websocket-client      # 唯一第三方依赖（CDP 读 DOM）
cp .env.example .env              # 填 HACKMATE_API_KEY
python chat.py                    # CLI 对话
python chat.py web                # 启动本机 Web 工作台（http://127.0.0.1:8765）
```

## Web 工作台

`python chat.py web` 在 `127.0.0.1:8765` 起一个本地服务（纯标准库 `http.server`，无前端构建链），自动打开浏览器。界面：

- **左侧**：CDP 已打开、或 HackMate 实际访问过的 HTTP(S) 页面。
- **中间上方**：工具行动记录；**中间下方**：你和 HackMate 的对话。
- **右侧**：工具入口（帮助 / 工作台 / 本地命令 / 存进度 / 记录 case / 读 skill / 提交 skill 优化 …）。

Web 工作台复用 CLI 的 `LLMClient` / `ToolContext` / `dispatch` / `schemas`，不重复实现对话与工具逻辑。抓包/改包、XSStrike 目前是界面占位项，尚未接入执行功能。GUI 暂不支持的 CLI 命令会在工作区提示，且不发给模型。

## 命令

```bash
python chat.py            # 对话（默认）
python chat.py web        # Web 工作台
python chat.py skill      # 列出漏洞知识
python chat.py cdp        # 列出 Chrome 页面
python chat.py memory     # 查看偏好 + 项目状态
```

对话内：`/help` `/clear` `/stop` `/web` `/cdp` `/cdp read N` `/guide` `/skill` `/memory` `/log` `/log steps` `/jobs` `/job N` `/cancel N` `/exit`

五 Agent 工作流入口：`/task <url>`。还支持 `/task status ID`、`/task recover ID`、`/task resume ID`。Web 工作台当前目标面板也提供工作流启动入口。必须先在 `config.json` 的 `authorized_scope` 中明确批准精确 origin、路径、HTTP 方法和 OBSERVE/TEST 操作级别；没有配置时工具默认拒绝。会改变状态的 HTTP 方法会按 IMPACT 处理，必须按具体工具名额外授权。示例（仅本地靶场）：

```json
{
  "authorized_scope": {
    "scope_id": "local-xss-lab",
    "approved": true,
    "origins": ["http://127.0.0.1:8080"],
    "path_prefixes": ["/"],
    "methods": ["GET"],
    "actions": ["OBSERVE", "TEST"],
    "approval_source": "user",
    "allow_private_network": true,
    "max_requests": 100,
    "requests_per_minute": 20
  }
}
```

靶场必须与授权 origin 完全匹配；选定工作台 Target 不等于授权。`IMPACT` 默认禁止；如需授权本地状态修改，需另外设置 `impact_approved: true` 和具体工具名组成的 `impact_actions`。`run_shell` 默认拒绝；通用 vendor CLI 目前也会拒绝执行，因为无法逐个检查它的重定向和实际请求，需先接入专用适配器。原始请求文件模式拒绝，因为无法可靠解析实际请求边界。

- **`/guide`** —— AI 教学引导：读当前靶场页面 → LLM 现场生成针对性步骤 → 在调试 Chrome 里用一个缓慢移动的「AI 光标」+ 说明气泡，一步步带你理解并利用这一关（纯页面注入，不动你真鼠标）。
- 浏览器工具使用一个**专用测试标签**：首次创建以保留原有标签，之后导航、读取、交互和验证都复用它。
- 开始任何一关前，先 `load_skill` 读对应漏洞的完整知识（测试方法 / 绕过手法 / 坑），不靠摘要裸打。

## 自主变强闭环（v2 起）

1. **后台 Job 模型（解卡死）**：慢活（eval 判分 / improve_skill）丢进后台 worker 线程，主循环永不阻塞，可随时 `/jobs` 看进度、`/cancel N` 中断、继续对话。
2. **语义判分阶梯（解假回滚）**：判一题走 `browser → fast → judge → fallback` 阶梯，语义评委对 regression + hidden 统一生效；`expected` 降级为喂评委的参考解，等价 payload 不再被误判。

## 判分可信度（让「变强」经得起推敲）

- **训练 / 考试隔离（防背题）**：`improve_skill` 只看 `dev`（训练集）的失败来改 skill；gate 的 before/after 只在 `regression + hidden`（留出考卷，improver 从不接触）上判分。三组互不重叠。`save_case` 打过的靶场沉淀进 `dev`。「变强」= 在没见过的题上真涨，而非记住喂进去的答案。
- **浏览器金标准**：带 `{payload}` 占位 `verify_url` 的 case，判分时把候选 payload 真塞进 URL、在 Chrome 里跑一遍看是否弹窗（`how=browser`）——地面真值优先于 LLM 评委，消解「同模型族自评」的循环论证。
- **CDP 卡死自愈**：浏览器工具在 WS 卡死 / 端点连不上时自动重启 Chrome 并重试一次，长跑判分不退化。
- **验证语义**：`verify_xss` 三态判定 —— CONFIRMED（观察到 `javascriptDialogOpening`）/ INCONCLUSIVE（未触发、不能排除）/ NOT_CONFIRMED（窄范围否定）。「payload 反射」不等于「XSS 成立」，alert 弹了才算。

## 三支柱 + 裁判

```
memory  长(long/)·中(project/current.md)·短(对话) + 步骤日志 log.jsonl
skill   skills/<vuln>/ 纯知识点（只能由 improve_skill 自己沉淀）+ cases + caution
tool    tools.py 表驱动注册表（cdp / skill / eval / memory）
eval    case → 产 payload → 判分阶梯 → gate（涨保留 / 跌回滚）
        训练=dev（可见）· 考试=regression+hidden（留出）· 判分优先走浏览器真验
```

## 目录

```
hackmate/   核心包：config/llm/log/memory/cdp/jobs/grader/eval/improver/skill/tools/repl
            + webui.py（Web 工作台服务）+ agent_link.py（跨 agent 对话入口）
hackmate/agents/        五 Agent 的 JSON role adapter（当前 Attacker 仅启用 XSS）
hackmate/orchestrator/  Python 状态机与任务持久化
hackmate/security/     Scope / Permission Gate
hackmate/evidence/     原始证据仓库和 SQLite 索引
hackmate/workflow/     CLI/Web 共用的工作流服务
schemas/               五 Agent 和共享对象的 JSON Schema 合同
docs/architecture/     基线、角色职责、流程和通信协议
skills/     漏洞知识（xss/，含 cases、运行时 backups）
evals/      eval case（schema v2：context/reference_payload/principle/verify_url/source）
memorys/    三层记忆 + 步骤日志
tests/      test_eval.py（grader/eval/gate）· test_jobs.py（Job 生命周期/取消）
hackmate/web/   Web 工作台前端（index.html）
```

## 依赖

纯标准库（urllib + json + threading + queue + http.server），唯一第三方 `websocket-client`（CDP 读 DOM）。Web 工作台同样零前端依赖。
