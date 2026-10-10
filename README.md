# HackMate

AI 渗透情报副驾驶。三支柱闭环：**memory（记了什么）· skill（懂什么）· tool（会用什么）**。

## 目录结构

```
HackMate/
├── chat.py                # 入口：python chat.py
├── hackmate/              # 核心包（纯标准库 + websocket-client）
│   ├── config.py          # 配置：环境变量 > .env > config.json > 默认
│   ├── llm.py             # OpenAI 兼容客户端（function calling）
│   ├── cli.py             # 对话循环 + 三支柱闭环 + 命令
│   ├── cdp.py             # CDP 浏览器工具实现
│   ├── memory.py          # 三层记忆（长/中/短）
│   ├── skill.py           # skill 加载/生成/改进（含 eval gate）
│   └── eval.py            # eval 裁判（case → grader → 分）
├── memorys/               # 三层记忆数据（见 memorys/README.md）
├── skills/                # 漏洞知识（见 skills/README.md）
├── tools/cdp/             # CDP 工具（schema.json + how2use.md + launcher/ 启动器）
├── evals/                 # eval 测试集（输入→期望）
```

## 运行

首次运行会引导粘贴 API key 并自动写入 `.env`：

```bash
python chat.py
```

或手动配置 `.env`（复制 `.env.example` 填 `HACKMATE_API_KEY`）。

## 对话命令

| 命令 | 作用 |
|---|---|
| `/help` | 帮助 |
| `/clear` | 清空上下文（短记忆） |
| `/cdp` `/cdp read N` `/cdp html N` | 查看 Chrome 页面 |
| `/skill` `/skill xss` | 查看 / 注入漏洞知识 |
| `/memory` | 查看长记忆 + 项目状态 |
| `/memory pref <text>` | 追加偏好（长记忆） |
| `/memory project <text>` | 写当前项目（中记忆） |
| `/memory reset-project` | 切项目：清空中记忆 |

## 设计原则

- **纯标准库**（urllib + json），唯一第三方依赖 `websocket-client`（读 DOM 用）。
- **OpenAI 兼容接口**，deepseek / openai / ollama / vllm 通用。
- **记忆三层仿 Hermes**：长（永久）/ 中（项目级）/ 短（对话级）。
- **skill 改进必过 eval gate**：分数涨保留、跌回滚，防黑箱盲改。
