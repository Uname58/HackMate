"""HackMate 三层记忆：长（永久）/ 中（项目级）/ 短（对话级）。

- 长记忆 memorys/long/：system_prompt.md（身份设定）+ preferences.md（用户偏好），永久保留。
- 中记忆 memorys/project/：current.md（当前项目状态），切换新项目时 reset。
- 短记忆：LLMClient.messages（对话上下文），新对话重置，不落盘。

读写时机（关键约定）：
- 长记忆写入：仅当用户显式表达偏好时（/memory 命令或代码调用 add_preference），避免堆垃圾。
- 中记忆写入：对话中关键进展（当前目标/发现）后。
- 短记忆：每轮对话自动追加，/clear 清空。
"""

import time
from pathlib import Path

from .config import app_root

BASE_DIR = app_root()  # HackMate 根目录
MEMORY_DIR = BASE_DIR / "memorys"
LONG_DIR = MEMORY_DIR / "long"
PROJECT_DIR = MEMORY_DIR / "project"

SYSTEM_PROMPT_FILE = LONG_DIR / "system_prompt.md"
PREFERENCES_FILE = LONG_DIR / "preferences.md"
PROJECT_FILE = PROJECT_DIR / "current.md"


def _ensure(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _read(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8")


def load_system_prompt() -> str:
    """读长期 system prompt（用户手写的身份/规则）。空则回退到 config 默认。"""
    return _read(SYSTEM_PROMPT_FILE).strip()


def load_preferences() -> str:
    """读用户长期偏好。"""
    return _read(PREFERENCES_FILE).strip()


def load_long_memory() -> str:
    """把长记忆拼成一段上下文（system prompt + 偏好）。"""
    parts = []
    sp = load_system_prompt()
    prefs = load_preferences()
    if sp:
        parts.append(sp)
    if prefs:
        parts.append("## User preferences\n" + prefs)
    return "\n\n".join(parts)


def load_project() -> str:
    """读当前项目的中记忆。"""
    return _read(PROJECT_FILE).strip()


def save_project(note: str) -> None:
    """写当前项目状态（中记忆，整体覆盖）。"""
    _ensure(PROJECT_FILE).write_text(note, encoding="utf-8")


def reset_project() -> None:
    """切换新项目：清空中记忆。"""
    _ensure(PROJECT_FILE).write_text("", encoding="utf-8")


def add_preference(text: str) -> None:
    """追加一条用户偏好到长记忆（带时间戳）。"""
    stamp = time.strftime("%Y-%m-%d %H:%M")
    entry = f"- [{stamp}] {text.strip()}\n"
    existing = _read(PREFERENCES_FILE)
    _ensure(PREFERENCES_FILE).write_text(
        existing + entry if existing else entry, encoding="utf-8"
    )
