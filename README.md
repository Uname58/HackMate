# HackMate v4

AI 渗透测试副驾驶（human-in-the-loop）。人类主导，AI 辅助侦察 / 分析 / 验证。多漏洞类型（XSS / SQLi / RCE / 文件上传 / 文件包含 / CSRF / 逻辑漏洞 …），按需加载知识 + 工具编排。

两条产品线：
- **CLI**（`chat.py`）—— 对话式打靶。
- **Web 工作台**（`chat.py web`）—— 本地 GUI，复用同一套对话与工具核心。

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
skills/     漏洞知识（xss/，含 cases、运行时 backups）
evals/      eval case（schema v2：context/reference_payload/principle/verify_url/source）
memorys/    三层记忆 + 步骤日志
tests/      test_eval.py（grader/eval/gate）· test_jobs.py（Job 生命周期/取消）
hackmate/web/   Web 工作台前端（index.html）
```

## 依赖

纯标准库（urllib + json + threading + queue + http.server），唯一第三方 `websocket-client`（CDP 读 DOM）。Web 工作台同样零前端依赖。
