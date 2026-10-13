"""三层记忆：长（永久）/ 中（项目级）/ 短（对话级）。

- 长 memorys/long/：system_prompt.md（身份设定）+ preferences.md（用户偏好），永久。
- 中 memorys/project/：current.md（当前项目状态），save_project 整体覆盖，重开保留。
- 短：LLMClient.messages（对话上下文），不落盘，/clear 清空。
"""

import time
from pathlib import Path

from .config import app_root

BASE_DIR = app_root()
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
    return p.read_text(encoding="utf-8") if p.exists() else ""


def load_system_prompt() -> str:
    return _read(SYSTEM_PROMPT_FILE).strip()


def load_preferences() -> str:
    return _read(PREFERENCES_FILE).strip()


def load_project() -> str:
    return _read(PROJECT_FILE).strip()


def save_project(note: str) -> None:
    """写当前项目状态（中记忆，整体覆盖）。"""
    _ensure(PROJECT_FILE).write_text(note, encoding="utf-8")


def reset_project() -> None:
    _ensure(PROJECT_FILE).write_text("", encoding="utf-8")


def add_preference(text: str) -> None:
    """追加一条用户偏好（带时间戳）。"""
    stamp = time.strftime("%Y-%m-%d %H:%M")
    entry = f"- [{stamp}] {text.strip()}\n"
    existing = _read(PREFERENCES_FILE)
    _ensure(PREFERENCES_FILE).write_text(existing + entry if existing else entry, encoding="utf-8")
