# HackMate v2 — 设计方案

> 从 0 重写。本文件是定稿设计 + 与 v1 的差异记录。

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
- 全部 mock LLM，不烧 API。`cd HackMate-v2 && python tests/test_eval.py && python tests/test_jobs.py`。

---

## ⑧ 待办 / 未做

- `verify_url` 目前迁移后的 case 多为空：browser 判分级暂不触发，靠评委语义判分。
  日后给 case 补 `{payload}` 占位的可复跑 URL，即可开启金标准真验。
- 多漏洞类型（DOM / Stored）知识已在 `skills/xss/` 保留，但闭环当前只锁 Reflected。
