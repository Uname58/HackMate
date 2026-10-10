# HackMate — Week 1 Closeout

> 第一周交付基线。冻结功能范围，记录已验证 / 未验证项。

## 项目定位

AI Red Team Copilot（渗透测试副驾驶），以 Human-in-the-Loop 为核心，提供有证据约束、有人类控制权的渗透测试辅助能力。差异化不在「会调用浏览器的 AI」，而在「能验证自身改进是否有效」。

## 第一周主题：核心安全边界建设

三支柱（memory / skill / tool）+ 一个裁判（eval）。

## 已完成 + 已验证

### 1. XSS 验证语义（三态）

- `CONFIRMED` / `INCONCLUSIVE` / `NOT_CONFIRMED` 三态，结构化返回 `status/evidence/reason/scope`。
- 黑盒路径只产出前两态；`NOT_CONFIRMED` 需读响应源码判断转义，第一周不实现（语义预留）。
- ✅ 真实 CDP 正向验证：`data:text/html,<script>alert(1)</script>` → `CONFIRMED`（dialog 消息 "1"）。
- ✅ 真实 CDP 阴性验证：无 alert 页面 → `INCONCLUSIVE`（未误报 `NOT_CONFIRMED`）。

### 2. Eval 分组

- `smoke(1)` / `dev(0)` / `regression(7)` / `hidden(预留)` 四组，`eval.load_group` 按组加载。
- 7 个 xss-labs 案例定位为**回归测试**（已知绕过），不承担评测责任。

### 3. 工具权限雏形

- 工具分类：只读 3 / 受控 5 / 高风险 0（留空）。
- 域名白名单（`HACKMATE_ALLOWED_HOSTS` / config.json），**默认拒绝**。
- 执行层强制：`_check_authorized` 在 `execute_tool` 前置检查。
- ✅ 权限负向测试 10 用例全过（空白名单 / 越界 / 空 host javascript:data: / 子域误匹配 / 重复调用 / fill_form 越界 tab）。

### 4. 三支柱架构

- `memory.py`（长/中/短三层）、`skill.py`（加载/改进含 eval gate）、`eval.py`（裁判）。
- 目录：`memorys/` + `skills/` + `tools/` + `evals/`。

## 尚未验证 / 未完成

- 持久化审计日志（当前权限拦截仅 stdout + 上下文，未落盘）。
- 隐藏泛化测试集（hidden 目录预留，未填充）。
- Skill 自动改进闭环（`improve_skill` 接口就绪，CLI 触发入口未接）。
- 正式版本审批 + 哈希证据链。

## 本周明确不做

- 不引入 Multi-Agent。
- 不接入自动 Skill 改进。
- 不实现完整版本审批与哈希证据链。
- 不扩展 DOM XSS / Stored XSS。
- 不宣称 7 个回归案例足以证明检测能力。

## 结论

三项最小改动已落地，并通过真实 CDP 验证 + 权限负向测试 + 回归测试。当前版本不宣称具备经过验证的自主 Skill 改进能力。下一步：推进 Skill 改进闭环的沉淀、评估与发布机制（待前三模块有更充分测试覆盖后）。
