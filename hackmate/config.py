"""配置加载：环境变量 > .env > config.json > 默认值。

纯标准库，无第三方依赖。
"""

import os
import json
from pathlib import Path

# 按顺序查找，先找到的先读
CONFIG_FILENAMES = [
    Path("config.json"),                        # 当前工作目录
    Path.home() / ".hackmate" / "config.json",  # 用户目录
]

DEFAULTS = {
    "api_key": "",
    "base_url": "https://api.deepseek.com/v1",
    "model": "deepseek-chat",
    "system_prompt": "You are a pentest copilot. Be concise, technical, and honest.",
    "cdp_host": "localhost",
    "cdp_port": 9222,
    "allowed_hosts": [],  # 授权测试的域名白名单（空 = 未授权任何目标，受控操作全拦截）
}


def _first_env(*names):
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return None


_DOTENV_PATHS = [
    Path(".env"),                        # 当前工作目录
    Path.home() / ".hackmate" / ".env",  # 用户目录
]


def load_dotenv(paths=None):
    """加载 .env 到 os.environ（不覆盖已存在的环境变量，遵循 dotenv 惯例）。

    纯标准库实现，支持 KEY=VALUE、引号包裹、# 注释、空行。
    """
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


def _parse_hosts(v):
    """把 allowed_hosts 解析成 list（支持 list / 逗号分隔字符串）。"""
    if isinstance(v, list):
        return [str(h).strip() for h in v if str(h).strip()]
    if isinstance(v, str):
        return [h.strip() for h in v.split(",") if h.strip()]
    return []


def load_config():
    load_dotenv()
    cfg = dict(DEFAULTS)

    # 1) config 文件（覆盖默认值）
    for p in CONFIG_FILENAMES:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[warn] 读取配置 {p} 失败: {e}")
                continue
            for key in ("api_key", "base_url", "model", "system_prompt", "cdp_host", "cdp_port"):
                if key in data and data[key]:
                    cfg[key] = data[key]
            if "allowed_hosts" in data:
                cfg["allowed_hosts"] = _parse_hosts(data["allowed_hosts"])

    # 2) 环境变量（最高优先级，覆盖 config 文件）
    v = _first_env("HACKMATE_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY")
    if v:
        cfg["api_key"] = v
    for env, key in (
        ("HACKMATE_BASE_URL", "base_url"),
        ("HACKMATE_MODEL", "model"),
        ("HACKMATE_SYSTEM_PROMPT", "system_prompt"),
        ("HACKMATE_CDP_HOST", "cdp_host"),
        ("HACKMATE_CDP_PORT", "cdp_port"),
    ):
        v = os.environ.get(env)
        if v:
            cfg[key] = v

    v = _first_env("HACKMATE_ALLOWED_HOSTS")
    if v:
        cfg["allowed_hosts"] = _parse_hosts(v)

    return cfg
