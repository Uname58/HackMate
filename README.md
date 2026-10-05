# HackMate

AI 渗透情报副驾驶。第一阶段：与 LLM 对话的最小 CLI。

## 运行

直接启动，**首次运行会引导你粘贴 API key 并自动写入 `.env`**（跨平台，不用记命令）：

```bash
python chat.py
```

或手动配置 `.env`：

```bash
# Linux / macOS
cp .env.example .env          # 然后编辑填入 key

# Windows PowerShell
Copy-Item .env.example .env   # 然后 notepad .env 填入 key
# 或临时环境变量（当前会话）：
$env:HACKMATE_API_KEY = "sk-xxx"
```

## 配置优先级

环境变量 > `.env` > `config.json` > 默认值。

| 项 | 环境变量 / .env 变量名 | 默认值 |
|---|---|---|
| api_key | `HACKMATE_API_KEY`（也认 `OPENAI_API_KEY` / `DEEPSEEK_API_KEY`） | 空 |
| base_url | `HACKMATE_BASE_URL` | `https://api.deepseek.com/v1` |
| model | `HACKMATE_MODEL` | `deepseek-chat` |
| system_prompt | `HACKMATE_SYSTEM_PROMPT` | pentest copilot |

> `.env` 文件在项目根目录或 `~/.hackmate/.env` 均可。真实环境变量优先于 `.env`（不会被覆盖）。

## 对话命令

- `/help` 帮助
- `/clear` 清空上下文
- `/exit` 退出

## 设计原则

- **纯标准库**（urllib + json + readline），零第三方依赖，换机即跑。
- **OpenAI 兼容接口**，deepseek / openai / ollama / vllm 通用。
- **`.env` 自解析**（不用 python-dotenv），敏感信息不落仓库（见 `.gitignore`）。
- 目录结构为后续扩展预留：`browser/`（浏览器抽象）、`brain/`（决策）、`memory/`（记忆分层）。
