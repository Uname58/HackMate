# HackMate v2

Human-in-the-loop AI 渗透测试副驾驶（red team copilot）。人类主力测试，AI 辅助侦察 / 源码分析 / 注入点 / payload / 验证。

**核心卖点是「自主变强闭环」**：打靶场 → 自动沉淀经验成 skill → eval gate 验证「变强没变弱」→ 涨保留 / 跌回滚。差异化在于能**验证自身改进是否有效**，而非被动问答。当前闭环能力面锁定 **Reflected XSS**（DOM / Stored 的知识文件在 `skills/` 保留，但闭环只锁反射型）。

> 架构定稿与 v1 差异记录见 [DESIGN.md](DESIGN.md)。本文件只放定向信息与随时间变化的状态。

## 技术栈 / 硬约束（改动别违背）
- **纯 Python 零第三方依赖**，唯一例外 `websocket-client`（CDP 读 DOM / 监听 dialog）。网络层用 `urllib`，并发 `threading`+`queue`，配置纯标准库自解析 `.env`（不引 `python-dotenv`）。
- **LLM**：OpenAI 兼容端点，默认 deepseek。双模型分工——快模型 `deepseek-chat`（`HACKMATE_MODEL`，打靶主对话+产 payload 判分+评委）；慢模型 `deepseek-v4-pro`（`HACKMATE_SKILL_MODEL`，读整份 skill 产改进候选，**写全 `v4-pro`**）。
- 配置优先级：环境变量 > `.env` > `config.json` > 默认值。
- **skill = 纯知识点**（不带 lab 内容），**只能由 HackMate 自己 `improve_skill` 沉淀，绝不人工代写**（否则破坏「自主变强」设定）；lab = case，放 `skills/<vuln>/cases/`。**eval case 数据可人工修**（修 eval 数据 ≠ 代写 skill）。
- 跨平台换机即跑；运行时产物（`log.jsonl` / transcripts / backups / `hidden_round.json`）gitignore。
- **三承诺不变**：① 进度不丢（步骤日志注入 system prompt + `save_project` 兜底）② 自动记坑（`verify_xss` CONFIRMED 即 `save_case`）③ 自动改善 skill 且过 eval gate（涨留跌滚）。

## 架构速查（细节见 DESIGN.md）
三支柱 + 裁判 + Job 层：**memory**（长 `long/` 永久 · 中 `project/current.md` 重开保留 · 短对话 + 步骤日志 `log.jsonl`）· **skill**（`skills/<vuln>/` 纯知识点 + cases + caution）· **tool**（`tools.py` 表驱动注册表）· **eval**（case → 产 payload → 判分阶梯 → gate）· **jobs**（后台单 worker 线程，主循环不阻塞）。
模块（`hackmate/`，13 个）：`config` · `llm` · `repl` · `jobs` · `tools` · `cdp` · `memory` · `grader` · `eval` · `improver` · `skill` · `log`。

关键机制：
- **语义判分阶梯** `browser → fast → judge → fallback`，对 regression + hidden 统一生效（解 v1「expected 字面匹配→等价 payload 假低分→gate 假回滚」）。expected 降级为喂评委的参考解。
- **训练/考试隔离（防背题）**：`improve_skill` 只从 `dev`（训练集，improver 可见）的失败反哺；gate 的 before/after 只在 `regression + hidden`（留出考卷，improver 永不接触）上判分。三组 id 互不重叠。`save_case` 自动沉淀的 case 写入 **`dev`**（打过的靶场=训练材料），不写考卷。「变强」= 在没见过的题上真涨，而非记住喂进去的答案。

## 关键设计决定（已确认）
- **v2 从 0 重写**（闭环是机制性问题，补丁不如重排），落在桌面同级新文件夹 `HackMate-v2`，与 v1 并存，验证通过前 v1 保持可跑。
- 后台用**单 worker 线程**（非 asyncio）：贴合现有同步/阻塞 socket/阻塞 stdin，零依赖够用。
- case schema v2：`context / reference_payload / principle / verify_url / source`，清掉 v1 的 expected/keyword/grader 混用。
- 工具**表驱动**，删 `tools/*/schema.json` + `how2use.md`，schema 与 handler 合一=单一真相源。
- **权限层去掉**（v1 本就没落地）。
- CDP 原生 Windows **不走代理、直连启动 Chrome**（代理 bind `0.0.0.0:9222` 与 Chrome `127.0.0.1:9222` 重叠 → WinError 10048；代理只对 WSL 必需）。

## 当前状态（2026-10）
- v2 已完成交付：13 模块写完；import 自检 + 启动链路 + 两套测试全绿（`test_eval` 判分/gate、`test_jobs` 生命周期/取消）。eval schema v2，L2/L6 错误参考解已修。`skills/xss` 整树 + `memorys/long/system_prompt.md`（人格设定）已带过来。
- **eval 分组（2026-10 训练/考试隔离后）**：dev 24（训练）/ regression 7 / hidden 27（考卷）/ smoke 1。老 hidden 是 xss-labs(按关)+PortSwigger 场景的混杂堆积且大量重复，已去重并按关卡交替分成 dev/hidden，备份在 `evals/xss/backups_split`。注意：考卷里仅 2 条带 `{payload}` 的 verify_url，其余靠 judge 判——待补 verify_url 上浏览器金标准。
- **CDP WinError 10048 已修**：根因是 `launch_chrome` 无条件用 WSL launcher 代理（bind 0.0.0.0:9222）与直连 Chrome 抢端口；已加 `_is_wsl()` 门控，原生 Windows/Git Bash 直连。`/cdp` 端到端验证通过。
- v1：xss-labs 20 关打完（16 CONFIRMED + 4 不可行），解法已 `save_case`，保持可跑未动。

## 待办（按优先级）
- [x] `/cdp` WinError 10048 修复（`_is_wsl()` 门控，直连）。
- [x] 跑通一次完整采集闭环：`navigate → find_xss_entries → verify_xss CONFIRMED → save_case`（xss-labs L1-20 自主跑，7/20 CONFIRMED）。
- [x] 训练/考试隔离：save_case→dev，gate 判 reg+hidden，三组不重叠。
1. **提升打关率 / verify oracle**：L1-20 自主跑仅 7/20，13 关打到 max_rounds=40 未收敛。真因：① `verify_xss` 只"导航+等弹窗"，需点击/悬停触发的关（如 L8 href `javascript:`）永远验不出——要加点击/事件模拟；② max_rounds 太浅且每关清上下文、慢模型没参与打关。
- [x] browser 金标准（2026-10）：8 个 case 补上 `{payload}` 的 `verify_url`（regression 3/7、dev 3、hidden 2，仅本地无需登录的 xss-labs，自校验写入）；`improve_skill`/eval 接真 CDP，带 vu 的题判分走浏览器真验（`how=browser`），CDP 不就绪/异常自动退回 judge。DVWA 不补 vu（依赖登录会话，eval 时过期会假阴性）；带过滤的关多数通用候选弹不出，留 judge。
- [x] 调试 Chrome 卡死自愈（2026-10）：`cdp.py` 加 `CDPClient.restart()` + `_resilient()`，所有浏览器工具（verify_xss/navigate/find/fill/click）在 WS 卡死（`_WS_ERRORS`）或端点连不上（`CDPConnError`）时自动杀 chrome→重启→重取 tab→重试一次。实测杀死 Chrome 后 verify 自愈 CONFIRMED。根因（反复密集 WS 后握手超时）未深究，但自愈已兜住。
- [x] 验证 gate（2026-10）：`improve_skill xss/reflection_xss` 后台跑通，dev 3 失败反哺 → regression 43%→71%、hidden 60%→70%（均为 improver 未见的留出集）→ gate 保留。真泛化，非背题。
4. 拆大 skill 文件做可维护性优化；rubric 结构维度 + 单维度优化（借鉴 darwin-skill）；skill 变体种群 + eval 选留（darwin 式进化）。
5. 可选：把 v1 的中记忆 `project/current.md` 迁进 v2（当前从净开始）。
