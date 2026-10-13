# memorys/ — 三层记忆约定

## 结构

```
memorys/
├── long/                     # 长记忆（永久，跨项目/对话）
│   ├── system_prompt.md      # 身份设定（非空时覆盖 config 默认）
│   └── preferences.md        # 用户偏好
└── project/                  # 中记忆（项目级，新项目 reset）
    └── current.md
```

## 短记忆

不落盘，是 `LLMClient.messages`（对话上下文），新对话重置。

## 读写时机

- **长记忆写入**：仅当用户显式表达偏好（`/memory pref`），避免堆垃圾。
- **中记忆写入**：对话关键进展后（`/memory project`）。
- **短记忆**：每轮自动追加，`/clear` 清空。
