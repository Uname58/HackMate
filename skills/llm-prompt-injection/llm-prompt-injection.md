# LLM / Prompt Injection / RAG / Agent — 决策索引

## 一句话说清
LLM 应用的攻击面 = 用户输入会被拼接到 prompt → 攻击者诱导模型执行非预期行为。
最高价值：**Agent 工具调用**——LLM 后面接了 `read_file` / `exec_code` / `send_email` 这类工具，被骗就是真的命令。
SRC 价值：能让 Agent 调出"不该给的工具"= P1–P0；能让模型回流系统 prompt / 训练数据 = P2–P1。

## 子类型路由（按信号读对应 variant）
| 入口信号 | MUST Read |
|---|---|
| 用户能直接喂 prompt 给 LLM(chat / completion / 助手类应用)| `10-direct-prompt.md`(基础 payload)+ `14-techniques.md`(100+ 技法) |
| LLM 会从文档 / 网页 / RAG 向量库读取内容 | `11-indirect-rag.md`(间接 / RAG 投毒) |
| 目标是 Agent 平台(可调用工具 / 浏览网页 / 跑代码) | `12-agent-vulns.md`(10 类 Agent 漏洞) |
| 目标可被探查模型本身(模型窃取 / 对抗样本) | `13-model-attacks.md` |
| payload 被拦,要 jailbreak / 绕过对齐 | `14-techniques.md`(技法 #2-#6 / 边界操纵 / 认知控制) |