"""HackMate 关键事件日志：记录并展示最近的重大事件。

事件类型（kind）：
- 结果类（/log 显示）：
  - skill：发现 / 改进漏洞知识（improve_skill 通过 eval gate）
  - vuln ：黑盒验证确认漏洞（verify_xss CONFIRMED）
  - case ：靶场通关后沉淀 eval case（save_case）
- 步骤类（/log steps 显示）：
  - step ：关键工具调用（枚举注入点 / 导航探测 / 验证 / 交互 / 保存状态）

数据文件：memorys/log.jsonl（每行一条 JSON，纯标准库，零依赖）。
"""

import json
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from .config import app_root

BASE_DIR = app_root()
LOG_FILE = BASE_DIR / "memorys" / "log.jsonl"

# 结果类事件（/log 显示）
RESULT_KINDS = {"skill", "vuln", "case"}

# 关键步骤工具：调用后记一笔 step（排除 list_tabs / read_page_text 观察型；
# save_case / improve_skill 已有结果记录，不进 step 避免重复）
KEY_STEP_TOOLS = {
    "open_new_tab",
    "navigate",
    "find_xss_entries",
    "verify_xss",
    "fill_form",
    "click",
    "save_project",
}


def _ensure() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def record(kind: str, **data) -> None:
    """追加一条事件。"""
    _ensure()
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind}
    entry.update(data)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def record_step(name: str, args: dict, result: str = "") -> None:
    """关键工具调用后记录一条步骤。非关键工具不记。"""
    if name not in KEY_STEP_TOOLS:
        return
    entry = {"tool": name}
    if name in ("open_new_tab", "navigate", "verify_xss"):
        entry["url"] = args.get("url", "")
    elif name in ("fill_form", "click"):
        entry["selector"] = args.get("selector", "")
    if name == "verify_xss":
        try:
            entry["status"] = json.loads(result).get("status", "")
        except Exception:
            pass
    record("step", **entry)


def _load_all() -> list:
    """加载全部日志条目（时间正序）。"""
    if not LOG_FILE.exists():
        return []
    entries = []
    for line in LOG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def recent(n: int = 10) -> list:
    """返回最近 n 条事件（时间正序）。"""
    return _load_all()[-n:]


def extract_params(url: str) -> list:
    """从 URL 提取查询参数 [(param, value), ...]，value 已 unquote。"""
    try:
        qs = urlparse(url).query
        if not qs:
            return []
        return [(k, unquote(v[0])) for k, v in parse_qs(qs, keep_blank_values=True).items()]
    except Exception:
        return []


def format_entry(e: dict) -> str:
    """单条事件 → 可读文本。"""
    ts = e.get("ts", "")
    kind = e.get("kind", "")
    if kind == "skill":
        action = "发现" if e.get("action") == "发现" else "改进"
        return f"[{ts}] {action}skill  {e.get('vuln', '')}/{e.get('variant', '')}"
    if kind == "vuln":
        url = e.get("url", "")
        params = e.get("params", [])
        line = f"[{ts}] 发现漏洞  {url}"
        if params:
            line += "\n        ↳ " + "  ".join(f"{k}={v}" for k, v in params)
        return line
    if kind == "case":
        return f"[{ts}] 沉淀case  {e.get('vuln', '')}  ({e.get('expected', '')})"
    if kind == "step":
        parts = [e.get("tool", "?")]
        if e.get("url"):
            parts.append(e["url"])
        if e.get("selector"):
            parts.append(e["selector"])
        if e.get("status"):
            parts.append(e["status"])
        return f"[{ts}] " + "  ".join(parts)
    return f"[{ts}] {kind}  {json.dumps(e, ensure_ascii=False)}"


def format_recent(n: int = 10) -> str:
    """最近 n 条「结果」事件（最新在前，只含 skill/vuln/case）。"""
    entries = [e for e in reversed(_load_all()) if e.get("kind") in RESULT_KINDS][:n]
    if not entries:
        return "还没有任何关键结果记录。"
    return "\n".join(f"{i + 1}. {format_entry(e)}" for i, e in enumerate(entries))


def format_steps(n: int = 20) -> str:
    """最近 n 条「步骤」事件（最新在前）。"""
    entries = [e for e in reversed(_load_all()) if e.get("kind") == "step"][:n]
    if not entries:
        return "还没有任何步骤记录。"
    return "\n".join(f"{i + 1}. {format_entry(e)}" for i, e in enumerate(entries))
