# HackMate v2

AI 渗透测试副驾驶（human-in-the-loop）。人类主导，AI 辅助侦察 / 分析 / 验证。当前聚焦 Reflected XSS。
核心卖点是「自主变强闭环」：打靶 → 沉淀 case → 带 eval gate 改 skill → 涨保留 / 跌回滚。

> v2 是 v1 的从 0 重写。相比 v1 解决了两个让闭环「跑不动」的根本问题，详见 `DESIGN.md`。

## 快速开始

```bash
pip install websocket-client      # 唯一第三方依赖（CDP 读 DOM）
cp .env.example .env              # 填 HACKMATE_API_KEY
python chat.py                    # 进入对话
python chat.py web                # 启动本机 Web 工作台（http://127.0.0.1:8765）
```

## 命令

```bash
python chat.py            # 对话（默认）
python chat.py skill      # 列出漏洞知识
python chat.py cdp        # 列出 Chrome 页面
python chat.py memory     # 查看偏好 + 项目状态
```

Web 工作台复用同一套 HackMate 对话与工具。左侧显示 CDP 已打开或 HackMate 实际访问过的 HTTP(S) 页面，中间上方显示工具行动记录、下方仅显示你和 HackMate 的对话，右侧列出工具入口。抓包/修改包和 XSStrike 当前是界面占位项，尚未接入执行功能。
在 GUI 输入 `/help` 会把帮助内容显示在中间工作区；输入 `/web` 会提示当前已在工作台中。GUI 暂不支持的 CLI 命令会在工作区提示，且不会发送给模型。

对话内：`/help` `/clear` `/stop` `/web` `/cdp` `/cdp read N` `/guide` `/skill` `/memory` `/log` `/log steps`
`/jobs` `/job N` `/cancel N` `/exit`

- **`/guide`** —— AI 教学引导：读当前靶场页面 → LLM 现场生成针对性步骤 → 在调试 Chrome 里用一个
  缓慢移动的「AI 光标」+ 说明气泡，一步步带你理解并利用这一关（纯页面注入，不动你真鼠标）。
- HackMate 的浏览器工具使用一个专用测试标签：首次创建以保留原有标签，之后导航、读取、交互和验证都复用它。

## v2 两个根本变化

1. **后台 Job 模型（解卡死）**：慢活（eval 判分 / improve_skill）丢进后台 worker 线程，主循环永不阻塞，
   可随时 `/jobs` 看进度、`/cancel N` 中断、继续对话。
2. **语义判分阶梯（解假回滚）**：判一题走 `browser → fast → judge → fallback` 阶梯，语义评委对
   regression + hidden **统一生效**；`expected` 从死板闸门降级为喂评委的参考解，等价 payload 不再被误判。

## 判分可信度（让「变强」经得起推敲）

- **训练 / 考试隔离（防背题）**：`improve_skill` 只看 `dev`（训练集）的失败来改 skill；gate 的 before/after
  只在 `regression + hidden`（留出考卷，improver 从不接触）上判分。三组互不重叠。`save_case` 打过的靶场
  沉淀进 `dev`。「变强」= 在没见过的题上真涨，而非记住喂进去的答案。
- **浏览器金标准**：带 `{payload}` 占位 `verify_url` 的 case，判分时把候选 payload 真塞进 URL、在 Chrome
  里跑一遍看是否弹窗（`how=browser`）——地面真值优先于 LLM 评委，消解「同模型族自评」的循环论证。
- **CDP 卡死自愈**：浏览器工具在 WS 卡死 / 端点连不上时自动重启 Chrome 并重试一次，长跑判分不退化。

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
hackmate/   核心包（纯标准库）：config/llm/log/memory/cdp/jobs/grader/eval/improver/skill/tools/repl
skills/     漏洞知识（xss/，含 cases、运行时 backups）
evals/      eval case（schema v2：context/reference_payload/principle/verify_url/source）
memorys/    三层记忆 + 步骤日志
tests/      test_eval.py（grader/eval/gate）· test_jobs.py（Job 生命周期/取消）
```

## 依赖

纯标准库（urllib + json + threading + queue），唯一第三方 `websocket-client`（CDP 读 DOM）。
