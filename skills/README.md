# skills/ — 漏洞知识约定

## 结构

```
skills/<vuln>/                # 一个 vuln 大类一个目录（xss / sqli / cmdi ...）
├── <vuln>.md                 # vuln 层总览（是什么、几大类、通用测试框架）
├── <variant>.md              # 类型层（reflection_xss / dom_xss / stored_xss ...）
├── caution.md                # 负向：踩过的坑 / 预警（别踩什么）
└── cases/                    # 案例（yyyy-mm-dd-which-attack.txt）
```

## 铁律（skill vs case 严格分离）

1. **skill.md = 纯知识点**（方法论 / 绕过 / 防御 / 通用 payload 模板），**绝不带 lab 内容**。
2. **case = 案例**，一个案例一个文件，命名 `yyyy-mm-dd-which-attack.txt`。
3. **skill 和 case 严格分离**：lab 通关归 `cases/`，不进 skill.md。
4. 命名小写下划线（`reflection_xss`，不是 `Reflection_XSS`）。

## skill.md vs caution.md

- `skill.md`：正向「怎么做」。
- `caution.md`：负向「别踩什么」。两者互补，别互相抄。

## 改进（B.3：根据行动生成/改进 skill）

必须过 **eval gate**（`hackmate/skill.py` 的 `improve_skill`）：改进前记分 → 写新内容 → 改进后记分 → 分数跌则自动回滚。没有 eval 验证的「自主改进」= 黑箱盲改。
