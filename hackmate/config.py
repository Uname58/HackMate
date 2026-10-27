"""配置加载：环境变量 > .env > config.json > 默认值。纯标准库。

v2 变化：去掉所有权限 / scope 相关配置（v1 文档描述但代码未落地，按设计决定删除）。
"""

import os
import sys
import json
from pathlib import Path

CONFIG_FILENAMES = [
    Path("config.json"),
    Path.home() / ".hackmate" / "config.json",
]

DEFAULTS = {
    "api_key": "",
    "base_url": "https://api.deepseek.com/v1",
    "model": "deepseek-chat",
    "skill_model": "deepseek-v4-pro",
    "system_prompt": "You are a pentest copilot. Be concise, technical, and honest.",
    "cdp_host": "localhost",
    "cdp_port": 9222,
    "mcp_servers": [],
}

# 这些 key 允许被 config 文件 / 环境变量覆盖
_KEYS = ("api_key", "base_url", "model", "skill_model", "system_prompt",
         "cdp_host", "cdp_port", "mcp_servers")


def app_root():
    """HackMate 根目录。打包成 exe 时用 exe 所在目录，开发时用源码上级目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _first_env(*names):
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return None


_DOTENV_PATHS = [
    Path(".env"),
    Path.home() / ".hackmate" / ".env",
]


def load_dotenv(paths=None):
    """加载 .env 到 os.environ（不覆盖已存在环境变量，遵循 dotenv 惯例）。"""
    for p in paths or _DOTENV_PATHS:
        p = Path(p)
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value


def load_config():
    load_dotenv()
    cfg = dict(DEFAULTS)

    for p in CONFIG_FILENAMES:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[warn] 读取配置 {p} 失败: {e}")
                continue
            for key in _KEYS:
                if key in data and data[key]:
                    cfg[key] = data[key]

    v = _first_env("HACKMATE_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY")
    if v:
        cfg["api_key"] = v
    for env, key in (
        ("HACKMATE_BASE_URL", "base_url"),
        ("HACKMATE_MODEL", "model"),
        ("HACKMATE_SKILL_MODEL", "skill_model"),
        ("HACKMATE_SYSTEM_PROMPT", "system_prompt"),
        ("HACKMATE_CDP_HOST", "cdp_host"),
        ("HACKMATE_CDP_PORT", "cdp_port"),
    ):
        v = os.environ.get(env)
        if v:
            cfg[key] = v

    return cfg
