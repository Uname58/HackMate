# HackMate

AI 渗透测试副驾驶。人类主导，AI 辅助侦察 / 分析 / 验证。当前聚焦 XSS（Reflected / DOM / Stored）。

## 快速开始

```bash
pip install websocket-client   # 唯一第三方依赖（CDP 读 DOM）
cp .env.example .env           # 填 HACKMATE_API_KEY（deepseek/openai/ollama 通用）
python chat.py
```

## 命令

```bash
python chat.py            # 进入对话（默认）
python chat.py skill      # 列出漏洞知识
python chat.py cdp        # 列出 Chrome 页面
python chat.py cdp read 0 # 读第 0 页可见文本
python chat.py memory     # 查看偏好 + 项目状态
```

对话内：`/help` `/clear` `/cdp` `/cdp read N` `/skill` `/memory` `/log` `/log steps` `/stop` `/exit`

## 怎么工作

三支柱 + eval 裁判，构成「自主变强闭环」：

- **memory**：长（偏好/设定）· 中（项目状态，LLM 自动 `save_project`）· 短（对话上下文）+ 步骤日志
- **skill**：`skills/<vuln>/` 漏洞知识，打靶后 LLM 自动 `improve_skill` 改进（过 eval gate，涨保留 / 跌回滚）
- **tool**：CDP 浏览器工具 + `save_case` 沉淀 eval case
- **eval**：思路 B——LLM 带 skill 产 payload 对 `expected` 判分，N 次取成功率；hidden 集防过拟合

三个可靠性承诺：

- **进度不丢**：步骤日志自动注入 system prompt，重开 / 卡住后可恢复
- **自动记坑**：`verify_xss` CONFIRMED 即 save_case，不依赖靶场 Solved 标记
- **自动改善 skill + eval 不回滚**：skill 改进必须过 eval gate

## 双模型分工

打靶场（快速试错）用 `deepseek-flash`；skill 候选生成（深度提炼）用 `deepseek-v4-pro`。改 `.env` 的 `HACKMATE_MODEL` / `HACKMATE_SKILL_MODEL` 切换。

## 目录

```
hackmate/   # 核心包（纯标准库）：config/llm/cli/cdp/memory/skill/eval/log
memorys/    # 三层记忆 + 步骤日志（long / project / log.jsonl）
skills/     # 漏洞知识（xss/ 含 cases、backups）
tools/      # LLM 工具（cdp / skill / memory / eval，schema.json + how2use.md）
evals/      # eval case（dev / regression / hidden 防过拟合）
```

## 依赖

纯标准库（urllib + json），唯一第三方 `websocket-client`（CDP 读 DOM）。
