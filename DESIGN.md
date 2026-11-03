# HackMate v4 — 设计方案

> v4 在 v3（Web 工作台）基础上，砍「skill 只能自主生成」红线，扩多漏洞类型 + 工具编排 + 按需加载。
> v2 的架构设计（后台 Job / 语义判分阶梯 / 自我进化闭环）仍有效，见下文「v2 设计」。

## 正式后续架构基准：五 Agent（2026-11-02）

后续架构按 **Contract-first → Orchestrator → Reflected XSS Vertical Slice → Evaluation → 扩展** 推进。Agent 职责：Recon 只收事实；Analyze 建立假设和测试计划；Attacker 按计划执行并保存证据；Reporter 独立检查原始证据并评估发现；Commander 是唯一面向用户的角色，负责整体调度和汇报。Python Orchestrator 控制阶段顺序、状态、重试和恢复；各阶段通过版本化 JSON Schema 交接，避免自由聊天式协作。采用工具执行 + LLM 推理的 Hybrid Multi-Agent，不要求五个独立模型。

### 里程碑

- **M0 — Baseline & Protection：完成记录。** 只读盘点了当前入口、复用点、未提交改动及现有测试基线，见 [`docs/architecture/migration-baseline.md`](docs/architecture/migration-baseline.md)。工作区原有修改必须保留。
- **M1 — Agent Contracts：首版草案已落盘，尚待冻结。** 五份职责合同、交接流程和共享 JSON Schema 位于 [`docs/architecture/`](docs/architecture/) 与 [`schemas/`](schemas/)；已加入标准库子集校验器，尚未完成合同评审和版本冻结。
- **M2 — Orchestration Foundation：首版已实现，仍需硬化。** 已加入 SQLite TaskStore/state machine、Scope Gate、EvidenceRepository、Schema 校验、预算/取消/恢复和 CLI/Web 工作流入口。每个任务复用同一个 Gate，配额与 DNS 观察状态会跨 Agent 阶段及任务恢复持久化。Gate 校验授权域名、解码后路径、方法、配额、DNS 地址变化及 CDP 重定向；非安全 HTTP 方法升级为 IMPACT，需按工具逐项授权。Skill Eval 的 browser-backed case URL 也会经过 Scope Gate；未授权 case 会在调用模型前拒绝。Gate 尚未把 DNS 地址固定到传输层，真实环境仍需专项验证。通用 vendor CLI 与 shell 当前 fail-closed，待逐请求适配后再开放。
- **M3 — Reflected XSS 集成：首条切片通过隔离本机端到端验证。** Recon adapter 把 `enumerate_site` 输出整理为端点和输入参数；Attacker 每轮提出一个工具动作，工具须同时在适配器允许列表和 Analyze 计划中。每轮执行保存独立原始证据，默认最多 3 轮（上限 5）。Reporter 从 EvidenceRepository 重新读取证据；XSS 接受条件还要求原始请求、响应关联同一 endpoint/参数值，并存在原始 CDP JavaScript 执行事件。离线 fake model/CDP 流程通过；另用临时本机反射页面、真实 Chrome/CDP 和合成测试授权验证了流程，Reporter 接受并保存 Request/Response/CDP/截图/Finding/Writeup。真实 LLM 和用户指定授权靶场仍待验证。
- **M4 — Evaluation & Reliability：离线基础已实现，真实环境待验证。** SQLite 持久化阶段结果、运行历史和有界的 Reporter 反馈循环；`needs_more_evidence` 可按预算重跑 Analyze/Attacker/Reporter，默认 1 次、上限 3 次。中断且 Attacker 结果未保存时拒绝自动重放。XSS VerifyState 按任务隔离，跨任务的缓存状态不作新任务的确认依据；EvidenceRepository 在写入和读取时校验证据 Schema。离线架构单测和工作流 Eval fixture 覆盖这些路径。Web Research 已接通 NVD 来源查询、候选登记、人工关联受控验证证据、现有 regression/hidden Eval、显式人工批准及 Skill improver。候选知识只作为生成建议输入；Skill 文件仅由现有 before/after Eval gate 保留或回滚。Research 和 Skill Eval 的浏览器请求也经过 Scope Gate，Skill 更新另需 IMPACT 授权。Research 是 Commander 按需调用的能力，不是第六个自由运行 Agent。真实 Agent 模型评估和完整回归集仍待补充。
- **M5 — 清理与扩展：部分完成。** 新增架构模块已按职责归入 `hackmate/agents/`、`orchestrator/`、`security/`、`evidence/`、`workflow/`，旧目录职责保持不变。后续漏洞适配器和大规模旧代码整理尚未开始。

首阶段不引入 Pydantic：现有运行时依赖约束是仅 `websocket-client`，M1 先以 JSON Schema 文件定合同；将来如需第三方校验库，应单独评估依赖影响。`memorys/`、`skills/`、`tools/`、`evals/` 的原有职责保持不变。

旧版 CLI/Web 自由对话路径仍保留；新增 `/task` 工作流由 Orchestrator 按阶段调度，尚未替换旧入口。Web 工作台的 Recon 按钮仍走旧的 LLM/工具对话路径；`_run_recon()` 是目前无调用方的遗留同源爬取函数，虽带 Scope Gate，不等于五 Agent Recon。工作流中工具分发有统一 Gate，MCP 没有显式策略时默认拒绝；Reporter 会独立按 Evidence ID 读取原件，并把常见凭据脱敏后再交给模型。脱敏是尽力而为，截图当前作为二进制证据保存，但文字型 Reporter 不会视觉读取截图。真实执行链仍待本地/授权环境验证。

架构目标不限定 XSS：首个闭环先做 Reflected XSS，后续按独立 Adapter + Skill + Evidence Rule + Eval 扩展 SQLi、CMDi、信息泄露和 WordPress 组件/CVE 测试。当前 Attacker 对其他漏洞类型会明确 BLOCKED，不会复用 XSS 工具误测。

## v4 设计（2026-10-22 定稿）

### 三个根本变化（相对 v3）

1. **砍「skill 只能自主 improve 生成」红线** —— 允许人工铺地基（嵌 src-hunter 多漏洞类型知识），
   improve/eval 在这个地基上继续自主长。理由：自主 improve 只能从 save_case 的打靶里长出来，
   XSS 之外的漏洞类型永远长不出，导致打 mystery lab / WordPress「找不到」。
2. **skill 从「全量加载」→「按需加载」** —— 一个 vuln 全读进上下文的设计，吃不下 27 万行的
   多漏洞知识。改成「路由表 + 按需 Read」：命中入口信号才翻对应 playbook。
3. **工具层扩展（双轨）** —— REGISTRY 内置核心工具（CDP/recon）+ MCP 客户端接外部工具
   （jshookmcp 等）+ vendor/ 第三方工具 adapter（sqlmap/dalfox/beef…）+ CVE 查询工具。

### 三层蓝图

- **知识层**：多漏洞类型 skill（嵌 src-hunter 19 类）+ 按需加载（路由表）
- **工具层**：REGISTRY（内置）+ MCP（外部）+ vendor adapter（CLI 工具）+ CVE 查询（NVD / GitHub Advisory / WPScan）
- **执行层**：LLM 自主调度「翻书 + 调工具 + 查 CVE」，串成攻击链

### 开发顺序

1. 按需加载（skill 路由表 + 按需 Read）
2. 嵌知识（src-hunter 19 类 → skills/ 多漏洞类型地基）
3. 接工具（vendor 9 工具 adapter + MCP 客户端 + CVE 查询）

### vendor/ 第三方工具（2026-10-22 已下载）

blindx / 4-zero-3 / waf-bypass / beef / dalfox / sqlmap / commix / fuxploider / phpsploit
（`git clone --depth 1`，`.git` 已删，`.gitignore` 忽略，不进仓库）
wafw00f（Python，WAF 识别）+ wpscan（`wpscanteam/wpscan` Docker，WordPress 枚举）+ whatweb（`azurielus/whatweb` Docker，技术栈指纹）

### 2026-11 设计增量（定位 / 能力模型 / verify 三机制 / 判型方法论）

#### 核心定位（人机分工）
HackMate = 自动寻找+验证**技术类漏洞**，人类做**逻辑类漏洞**：
- AI 做技术类：XSS / SQLi / CMDi / Information Disclosure / File Upload / WordPress 组件 CVE 验证 —— 通过「明确输入→规则→可验证结果」逐类实现；当前五 Agent 首个完整切片是 Reflected XSS，其他类型尚未接入该工作流。
- 人类做逻辑类：业务逻辑 / 越权 / 竞态（需理解业务意图），HackMate 帮人快速分析网站架构（recon）

#### 能力模型（分析/验证/评估，每个漏洞模块都按这三段拆）
1. **分析**：架构侦察 + sink 分析（判断漏洞类型 + 注入点/上下文）
2. **验证**：客观真值信号（XSS=alert 金标准、RCE=whoami、LFI=/etc/passwd、SQLi=拖库字段）+ verify 三机制
3. **评估**：严重性（high vs critical、CVSS）、泄露是否敏感
成熟度：分析最成熟（recon 已跑通）> 评估偏弱（grader 未系统化）> 验证最难（AI 自嗨，只有 XSS 有金标准）

#### verify 三机制（`tools.py` VerifyState 类，验证可靠性补强）
数据源唯一 `memorys/verify.jsonl`，进程启动回放重建（`verify_ttl_days`=30 天失效窗口）：
1. **阴性对照**：verify CONFIRMED 前先测 baseline（无害输入 test123），baseline 也触发 → 降级 INCONCLUSIVE + `baseline_triggered_same_signal`
2. **全量落盘**：每次 verify 三态都写 verify.jsonl（ts/entry_id/payload/status/reason/evidence）
3. **查重 + 失败停止**：entry_id + payload（URL decode 归一，HTML entity/大小写不归一）已测 → 缓存返回；连续 `verify_max_consecutive_fail`(3) 次 INCONCLUSIVE → NOT_CONFIRMED + blocked
ToolContext 自动创建 verify_state（webui.py/repl.py 两处构造点不用改）

#### 判型方法论（数据流 sink 分析，已写进 system_prompt §7）
三个维度定测什么：输入点在哪 + 数据流向哪 + 技术栈。数据流（sink）是本质——拼 SQL→SQLi、渲染 HTML→XSS、当路径→LFI、当命令→cmdi、当 XML→XXE、当 URL→SSRF/redirect、反序列化、模板→SSTI。⚠️ 数据库类型定 SQLi 手法（MySQL `-- ` 带空格 / Oracle `--` / MSSQL `;--`）。另有功能/权限模型（多角色→越权、支付→竞态）+ 通用检查（CORS/备份文件/目录列表/默认凭据）。

#### 待办
- recon 指令（webui.py start_recon）还没接「技术栈识别用 whatweb、WordPress 用 wpscan」，工具已装好、LLM 可手动 run_tool 调
- 「skill 版本号变化失效」未实现（verify 查重失效窗口当前只有 30 天时间，无 skill 版本号机制）

#### 架构迁移状态（2026-11-02）
原「未来重构方向」已启动：五 Agent 合同、Orchestrator、证据仓库和权限 Gate 的首版位于 `docs/architecture/`、`schemas/` 和 `hackmate/` 对应子目录。`memorys/`、`skills/`、`tools/`、`evals/` 继续保留各自职责；SQLi、CMDi、信息泄露和 WordPress 适配器仍是后续工作，不表示已具备这些自动验证能力。

---

## v2 设计（历史定稿，仍有效）

> 从 0 重写。本文件是 v2 定稿设计 + 与 v1 的差异记录。

## 0. 总纲

**三承诺（最高优先级，不变）**
1. 进度不丢 —— 步骤日志 `log.jsonl` 注入 system prompt + 中记忆 `save_project` 兜底，重开/卡住可恢复。
2. 自动记坑 —— `verify_xss` CONFIRMED 即 `save_case`，不等靶场 Solved 标记。
3. 自动改善 skill 且 eval 不回滚 —— skill 改进必须过 eval gate（涨保留 / 跌回滚）。

**硬约束（不变）**
- 纯标准库零依赖，唯一例外 `websocket-client`（CDP 读 DOM）。
- skill = 纯知识点，只能由 HackMate 自己 `improve_skill` 沉淀，绝不人工代写；lab = case。
- 跨平台换机即跑；运行时产物 gitignore。

**v1 的病**：单线程同步 —— 所有慢活卡在 `input()` 循环里（improve_skill 阻塞 18–45 分钟），
而判分用 `expected` 字面匹配导致 regression 假低分、gate 假回滚。于是闭环既**卡死**又**跑不动**。

**v2 两个根本变化**：① 慢活进后台 Job；② 判分换成语义阶梯。

---

## ① 后台 Job 模型（解卡死）—— `jobs.py`

- **主线程 REPL + 单后台 worker 线程**（`threading` + `queue`，纯标准库）。主线程独占 stdin、永不阻塞。
- 一个慢任务 = 一个 **Job**：`id / kind / status(queued|running|done|failed|cancelled) / progress / result / cancel 标志`。
- worker 串行执行 Job（避免并发烧爆 API），线程安全更新 Job 记录，进度同时写步骤日志。
- 命令：`/jobs` `/job N` `/cancel N`；每轮 prompt 前冒泡已完成任务，并把结果作为一条上下文告知 LLM。
- **协作式取消**：执行函数在每次 LLM 调用之间 `job.check_cancel()`，不强杀线程（Python 杀不干净），
  最多残留一个在途请求、被 LLM 超时兜住。
- 顺带修了 v1 的**线程泄漏**（见 ⑥）。

## ② 语义判分阶梯（解假回滚）—— `grader.py` / `eval.py`

判一题走阶梯，语义优先，对 **regression + hidden 统一生效**（v1 评委只在 hidden）：

1. **browser（金标准，可选）**：case 带含 `{payload}` 占位的 `verify_url` 且 CDP 可用 → 真跑看 alert。
2. **fast（确定性正向捷径）**：参考解是候选子串 → 直接判过，省评委调用。**只判正、不判负**。
3. **judge（语义评委，判分权威）**：把「场景 + 参考解 + 原理 + 候选」喂独立评委，问是否真能解决。
   `onmouseover ≡ onclick` 在这里被认成等价。多评委共识：一否即否；评委异常跳过不误杀。
4. **fallback**：无评委时退回参考解子串匹配（向后兼容）。

关键转变：`expected` 从「死板闸门」降级为「喂评委的参考示例」—— 这是解开假回滚的核心。

**case schema v2**（清掉 v1 的 `expected`/`keyword`/`grader` 混用；grader 对 v1 字段做了回退兼容）：

```json
{
  "id": "xss-labs-L3",
  "context": "反射点落在属性值 value=\"...\" 内，htmlspecialchars 未加 ENT_QUOTES（单引号未转义）",
  "reference_payload": "' onmouseover='alert(1)",
  "principle": "单引号 breakout 进属性，注入事件处理器",
  "verify_url": "http://localhost:8080/level3.php?keyword={payload}",
  "source": "xss-labs"
}
```

**gate 回滚条件**（判分变语义后才真正有意义）：regression 严格跌 / hidden 跌幅 > 容差(5%) / 综合涨幅 < 早停(2%)。
每题 trials 次消随机性；保留 `.bak` 可回滚。整个 gate 作为后台 Job 跑，进度可见。

---

## ③ 自我进化闭环（端到端）

1. 打靶（主线程，对话 + cdp 工具）→ `verify_xss` CONFIRMED → `save_case`（schema v2）→ `save_project`。【承诺 2】
2. 步骤日志持续落盘 → 重启注入 system prompt 恢复现场。【承诺 1】
3. 出现可复用经验 → `improve_skill` → **提交后台 Job**，立即返回，主线程继续响应。【解卡死】
4. worker 跑 gate：before 判分（语义评委，全组，trials）→ 失败明细喂慢模型产候选 → after 判分 → gate 留/滚。【承诺 3】
5. 结束时主循环冒泡结果。

---

## ④ 模块布局

```
hackmate/
  config.py    env>.env>json>默认（去权限相关）
  llm.py       socket 超时无泄漏 + clone() 产独立判分 client
  repl.py      主线程 REPL：命令 + 对话 tool-loop + Job 冒泡
  jobs.py      ★ Job 模型 + 后台 worker + 线程安全 registry/queue
  tools.py     ★ 工具注册表（schema+handler 合一，表驱动，自动生成 function-calling 列表）
  cdp.py       浏览器（沿用）
  memory.py    三层记忆
  grader.py    ★ 判分阶梯 fast/judge/browser（可独立单测）
  eval.py      分组加载 + 轮换抽样 + trials 打分 + transcript（与 skill 解耦，靠回调拿内容）
  improver.py  ★ 慢模型候选生成（失败明细反哺）
  skill.py     加载/写/回滚/摘要 + gate + run_improvement（作 Job 跑）
  log.py       步骤/结果日志（+ job 事件）
```

拆分理由：v1 `skill.py` 把 eval-fn 构造、评委、候选 prompt、gate 全糊在一起，难测难改；
`cli.execute_tool` 是个大 if 链、与 schema.json 两头漂移。v2 切成 grader / eval / improver / skill / tools，
各自可单测，改进流程包成 Job。

---

## ⑤ 相对 v1 的删 / 改 / 留

- **删**：`tools/*/schema.json` + `how2use.md` 分离文件 → 工具内联进 `tools.py` 注册表（单一真相源）。
- **删**：文档描述但 v1 代码本就不存在的 scope/权限层（域名白名单、工具分类、默认拒绝、审计链）。
  结果：`navigate`/`verify_xss` 接受任意 URL。
- **改**：case schema v1→v2；L2/L6 两个自相矛盾的参考解在迁移时修正
  （修 eval 数据 ≠ 人工代写 skill 知识）。评委对所有分组统一生效。
- **留**：三支柱 + eval gate + 双模型 + 轮换抽样 + 失败反哺 + 早停 + 备份回滚；`skills/xss` 整树原样保留。

---

## ⑥ 关键实现要点

- **llm 无泄漏超时**：用 `urlopen(timeout=...)` 的 socket 级超时（超时即抛异常、socket 关闭），
  加有限重试预算控制总时长。v1 用 daemon 线程 + join，超时后线程仍跑、socket 不关 → 多次超时泄漏。
- **判分 client 隔离**：评委 / 产 payload / 候选生成都用 `LLMClient.clone()` 出独立上下文，不污染主对话。
- **双模型**：快模型（`HACKMATE_MODEL`）打靶 + 产 payload + 评委；慢模型（`HACKMATE_SKILL_MODEL`）产候选。

---

## ⑦ 测试

- `tests/test_eval.py`：grader 阶梯 / v1 schema 兼容 / eval 打分 + 失败反哺 / 轮换抽样 / gate 早停·防过拟合·防退化。
- `tests/test_jobs.py`：Job 生命周期 / 异常兜底 / 协作式取消 / 完成冒泡。
- 全部 mock LLM，不烧 API。`cd HackMate-v4 && python tests/test_eval.py && python tests/test_jobs.py`。

---

## ⑧ 待办 / 未做

- `verify_url` 目前迁移后的 case 多为空：browser 判分级暂不触发，靠评委语义判分。
  日后给 case 补 `{payload}` 占位的可复跑 URL，即可开启金标准真验。
- 多漏洞类型（DOM / Stored）知识已在 `skills/xss/` 保留，但闭环当前只锁 Reflected。
