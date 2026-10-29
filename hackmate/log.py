"""关键事件日志：记录 + 展示最近重大事件，并注入 system prompt 做进度恢复。

事件类型（kind）：
- 结果类（/log）：skill（发现/改进）· vuln（verify CONFIRMED）· case（沉淀 eval case）
- 步骤类（/log steps）：step（关键工具调用）· job（后台任务进度，v2 新增）

数据文件：memorys/log.jsonl（每行一条 JSON，纯标准库）。
"""

import json
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from .config import app_root

BASE_DIR = app_root()
LOG_FILE = BASE_DIR / "memorys" / "log.jsonl"

RESULT_KINDS = {"skill", "vuln", "case"}

KEY_STEP_TOOLS = {
    "open_new_tab", "navigate", "find_xss_entries", "verify_xss",
    "fill_form", "click", "save_project", "run_tool", "search_cve",
}


def _ensure() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def record(kind: str, **data) -> None:
    _ensure()
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind}
    entry.update(data)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def record_step(name: str, args: dict, result: str = "") -> None:
    if name not in KEY_STEP_TOOLS:
        return
    entry = {"tool": name}
    if name in ("open_new_tab", "navigate", "verify_xss"):
        entry["url"] = args.get("url", "")
    elif name in ("fill_form", "click"):
        entry["selector"] = args.get("selector", "")
    elif name == "run_tool":
        entry["vendor"] = args.get("tool", "")
        entry["cmd_args"] = args.get("args", "")
    elif name == "search_cve":
        entry["keyword"] = args.get("keyword", args.get("component", ""))
    if name == "verify_xss":
        try:
            entry["status"] = json.loads(result).get("status", "")
        except Exception:
            pass
    record("step", **entry)


def _load_all() -> list:
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
    return _load_all()[-n:]


def extract_params(url: str) -> list:
    try:
        qs = urlparse(url).query
        if not qs:
            return []
        return [(k, unquote(v[0])) for k, v in parse_qs(qs, keep_blank_values=True).items()]
    except Exception:
        return []


def format_entry(e: dict) -> str:
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
        return f"[{ts}] 沉淀case  {e.get('vuln', '')}  ({e.get('reference_payload', e.get('expected', ''))})"
    if kind == "job":
        return f"[{ts}] job#{e.get('job', '?')} {e.get('status', '')}  {e.get('note', '')}"
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
    entries = [e for e in reversed(_load_all()) if e.get("kind") in RESULT_KINDS][:n]
    if not entries:
        return "还没有任何关键结果记录。"
    return "\n".join(f"{i + 1}. {format_entry(e)}" for i, e in enumerate(entries))


def format_steps(n: int = 20) -> str:
    all_entries = _load_all()
    # A stop ends the prior execution context. Keep that boundary visible, but do
    # not inject stale navigation/tool calls from before it as current progress.
    last_stop = next((i for i in range(len(all_entries) - 1, -1, -1)
                      if all_entries[i].get("kind") == "task"
                      and all_entries[i].get("status") == "interrupted"), -1)
    entries = [e for e in all_entries[last_stop + 1:]
               if e.get("kind") in ("step", "job")]
    entries = entries[-n:]
    if last_stop >= 0:
        entries.insert(0, all_entries[last_stop])
    if not entries:
        return "还没有任何步骤记录。"
    return "\n".join(f"{i + 1}. {format_entry(e)}" for i, e in enumerate(entries))


def record_task_interrupted() -> None:
    record("task", status="interrupted", note="用户停止；任务未完成")
