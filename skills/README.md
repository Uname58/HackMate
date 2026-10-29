# skills/ — 漏洞知识约定

## 结构

```
skills/<vuln>/                # 一个 vuln 大类一个目录（xss / sqli / cmdi ...）
├── <vuln>.md                 # vuln 层总览（是什么、几大类、通用测试框架）
├── playbook.md               # 判断流程（★核心：判据、决策步骤、什么信号→怎么做）
└── <variant>.md              # 类型层（reflection_xss / dom_xss / stored_xss ...）
                              #   具体绕过手法，挂到判断规则下，每条最多 1 个最小示例
```

## 铁律（判断流程 vs payload 严格分离）

1. **playbook.md = 判断流程**：判据、决策规则、什么信号该停/换思路。payload 靠现场按上下文构造，**不背**。
2. **<variant>.md = 绕过手法**，但必须挂到判断规则下（「什么信号 → 用什么绕」），**不堆一列孤立 payload**。
3. **不写**：定义（是什么）、影响（Impact）、防御建议（Defense/CSP/HttpOnly）、工具清单、参考链接。
4. 命名小写下划线（`reflection_xss`，不是 `Reflection_XSS`）。

## 改进（B.3：根据行动生成/改进 skill）

必须过 **eval gate**（`hackmate/skill.py` 的 `improve_skill`）：改进前记分 → 写新内容 → 改进后记分 → 分数跌则自动回滚。没有 eval 验证的「自主改进」= 黑箱盲改。

improver（`hackmate/improver.py`）只产出「判断规则」，不堆 payload 字典。
