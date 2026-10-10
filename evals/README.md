# evals — HackMate 的「裁判」

验证 skill 更新 / payload 生成有没有用，防止黑箱盲改。

## 分组（dev / regression / hidden 分离）

```
evals/<vuln>/
├── smoke.json        # 验证 runner 能跑（最小 case）
├── dev.json          # 开发集：模型可看，用于改进 skill
├── regression.json   # 回归集：每次改动都跑，检查已知能力没退化
└── hidden/           # 隐藏集：不向改进模型公开，检查泛化（预留）
```

> 关键：不能只看总分。改进 skill 后必须**同时看 regression（有没有退化）**，并对关键安全约束设硬性门槛（误报率 / 漏报率）。

## case 格式

```json
[
  {
    "id": "xss-labs-L1",
    "input": "反射点落在文本节点，无过滤",
    "expected": "<script>alert(1)</script>",
    "grader": "contains"
  }
]
```

- `input`: 给 HackMate 的场景描述
- `expected`: 期望输出（payload / 关键 token）
- `grader`: `contains`（子串匹配）/ `regex`（正则）/ `browser`（CDP 真验证 alert）

## 怎么跑

```python
from hackmate import eval as ev
cases = ev.load_group("xss", "regression")

def produce(inp):
    # 这里接 LLM 让 HackMate 生成 payload
    return "..."

passed, total, details = ev.run_eval(cases, produce)
print(ev.format_report(passed, total, details))
```

## grader 优先级（从便宜到贵）

1. `contains` / `regex` — 弱检查，验证输出含关键 token。
2. `browser` — 强验证，CDP 真跑 payload，alert 弹了才算（XSS 的终极标准）。
