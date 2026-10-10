"""HackMate CLI —— AI 渗透副驾驶，三支柱闭环（memory / skill / tool）。

启动：python chat.py（在 HackMate 根目录）
"""

import sys
import json
from pathlib import Path

from .config import load_config
from .llm import LLMClient, LLMError
from . import memory, skill

BASE_DIR = Path(__file__).resolve().parent.parent  # HackMate 根目录
TOOLS_DIR = BASE_DIR / "tools"

# 工具权限分类 —— 权限边界在工具执行层强制（不靠 prompt）
READ_ONLY_TOOLS = {"list_tabs", "read_page_text", "find_xss_entries"}
CONTROLLED_TOOLS = {"navigate", "open_new_tab", "fill_form", "click", "verify_xss"}
HIGH_RISK_TOOLS = set()  # 第一周留空（改变业务数据 / 越权 / 破坏性操作）

BANNER = "HackMate v0.2 — AI 渗透情报副驾驶 (CLI)"

HELP = """命令:
  /help        显示本帮助
  /clear       清空上下文（保留 system prompt）
  /cdp         查看当前 Chrome 打开的页面（带序号，注入上下文）
  /cdp read N  读第 N 个页面的可见文本
  /cdp html N  读第 N 个页面的 DOM HTML
  /skill       列出可用的漏洞知识（skills/）
  /skill <vuln>  把某类漏洞知识注入上下文（如 /skill xss）
  /memory      查看长记忆 + 当前项目状态
  /memory pref <text>   追加一条偏好到长记忆
  /memory project <text>  写当前项目状态（中记忆）
  /memory reset-project   切换项目：清空中记忆
  /exit        退出（也可用 exit / quit / Ctrl+C）
  其它任意输入都会发给 LLM 对话（LLM 可自动调用浏览器工具）
"""


def load_tools():
    """从 tools/*/schema.json 加载 function calling 工具定义（给 LLM 的接口声明）。"""
    tools = []
    if not TOOLS_DIR.exists():
        return tools
    for schema_file in sorted(TOOLS_DIR.glob("*/schema.json")):
        try:
            data = json.loads(schema_file.read_text(encoding="utf-8"))
            tools.extend(data if isinstance(data, list) else [data])
        except Exception as e:
            print(f"[warn] 加载工具 schema {schema_file} 失败: {e}")
    return tools


def _host_from_url(url):
    """从 URL 提取 hostname（不带端口）。空 / 非法 URL 返回 ''。"""
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _authorized(host, allowed_hosts):
    """检查 host 是否在授权白名单。空白名单 = 未授权任何目标。"""
    if not host or not allowed_hosts:
        return False
    return host in allowed_hosts or any(host.endswith("." + h) for h in allowed_hosts if h)


def _target_host(name, args, cdp):
    """从工具参数提取目标 host（用于授权检查）。"""
    if name in ("navigate", "open_new_tab", "verify_xss"):
        return _host_from_url(args.get("url", ""))
    if name in ("fill_form", "click"):
        idx = int(args.get("index", 0))
        try:
            tabs = cdp.list_tabs()
            if 0 <= idx < len(tabs):
                return _host_from_url(tabs[idx]["url"])
        except Exception:
            pass
        return ""
    return ""


def _check_authorized(name, args, cdp, allowed_hosts):
    """权限检查。返回 None=放行，返回字符串=拦截原因。"""
    if name not in CONTROLLED_TOOLS and name not in HIGH_RISK_TOOLS:
        return None  # 只读工具，放行
    if name in ("navigate", "open_new_tab", "verify_xss"):
        url = (args.get("url") or "").strip()
        if url.lower() == "about:blank" or url == "":
            return None  # 空白页，无目标，放行
        host = _host_from_url(url)
    else:  # fill_form / click：作用在当前 tab
        host = _target_host(name, args, cdp)
    if not _authorized(host, allowed_hosts):
        return (f"权限拦截：目标 {host or '（无法解析的 URL，如 javascript:/data:）'} 不在授权白名单。"
                f"当前授权：{allowed_hosts or '无'}。需人工授权后才能执行。")
    return None


def build_system_prompt(cfg):
    """闭环起点：长记忆（system prompt + 偏好）+ skill 目录摘要 拼成 system prompt。"""
    parts = []
    sp = memory.load_system_prompt()
    parts.append(sp if sp else cfg["system_prompt"])
    prefs = memory.load_preferences()
    if prefs:
        parts.append("## 用户偏好\n" + prefs)
    sk = skill.summary()
    if sk:
        parts.append(sk + "\n（用 /skill <vuln> 查看某类漏洞的完整知识）")
    return "\n\n".join(parts)


def main():
    cfg = load_config()

    if not cfg["api_key"]:
        print("首次运行，未检测到 API key。")
        key = input("请粘贴你的 API key（sk-...）: ").strip()
        if not key:
            print("未输入 key，退出。")
            return 1
        env_path = Path(".env")
        if env_path.exists():
            print(f"{env_path} 已存在，请手动编辑填入 key（格式 HACKMATE_API_KEY=sk-xxx）。")
            return 1
        env_path.write_text(f"HACKMATE_API_KEY={key}\n", encoding="utf-8")
        print(f"已写入 {env_path}，重新加载配置...")
        cfg = load_config()
        if not cfg["api_key"]:
            print("配置加载失败，请检查 .env 内容。")
            return 1

    system_prompt = build_system_prompt(cfg)
    client = LLMClient(cfg["base_url"], cfg["api_key"], cfg["model"], system_prompt)

    tools = load_tools()
    allowed_hosts = cfg.get("allowed_hosts", [])

    print(BANNER)
    print(f"模型: {cfg['model']}  |  端点: {cfg['base_url']}")
    print(f"已加载 {len(tools)} 个浏览器工具 | 可用漏洞知识: {', '.join(skill.list_vulns()) or '无'}")
    print("输入 /help 查看命令，直接输入文字开始对话。\n")

    try:
        import readline  # 提供历史记录/行编辑，Windows 原生环境可能没有，忽略即可
    except ImportError:
        pass

    # CDP 懒加载
    _cdp = {"client": None}

    def ensure_cdp_client():
        if _cdp["client"] is None:
            from .cdp import ensure_cdp
            _cdp["client"] = ensure_cdp(cfg["cdp_host"], int(cfg["cdp_port"]))
        return _cdp["client"]

    def execute_tool(name, args):
        """执行 LLM 请求的工具，返回结果字符串。"""
        cdp = ensure_cdp_client()
        if cdp is None:
            return "错误：CDP 未就绪，无法执行浏览器操作"

        # 权限边界：受控/高风险操作先过授权检查（模型请求 ≠ 操作获准）
        deny = _check_authorized(name, args, cdp, allowed_hosts)
        if deny:
            print(f"  [权限] {deny}")
            return deny
        try:
            if name == "list_tabs":
                tabs = cdp.list_tabs()
                return json.dumps(
                    [{"index": i, "title": t["title"], "url": t["url"]} for i, t in enumerate(tabs)],
                    ensure_ascii=False,
                )
            if name == "open_new_tab":
                tab = cdp.open_new_tab(args.get("url", "about:blank"))
                return json.dumps(
                    {"opened": tab.get("title", ""), "url": tab.get("url", "")},
                    ensure_ascii=False,
                )
            if name == "read_page_text":
                tabs = cdp.list_tabs()
                idx = int(args.get("index", 0))
                if not (0 <= idx < len(tabs)):
                    return f"序号 {idx} 超出范围（0-{len(tabs)-1}）"
                return cdp.read_page_text(tabs[idx])
            if name == "navigate":
                return cdp.navigate(args.get("url", "about:blank"), int(args.get("index", 0)))
            if name == "fill_form":
                return cdp.fill_form(args["selector"], args["value"], int(args.get("index", 0)))
            if name == "click":
                return cdp.click(args["selector"], int(args.get("index", 0)))
            if name == "find_xss_entries":
                return cdp.find_xss_entries(int(args.get("index", 0)))
            if name == "verify_xss":
                return cdp.verify_xss(args["url"], int(args.get("index", 0)))
        except Exception as e:
            return f"工具执行错误: {e}"
        return f"未知工具: {name}"

    while True:
        try:
            line = input("你> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见~")
            break

        if not line:
            continue
        if line in ("/exit", "/quit", "exit", "quit"):
            print("再见~")
            break
        if line in ("/clear", "clear"):
            client.clear()
            print("上下文已清空。")
            continue
        if line in ("/help", "help"):
            print(HELP)
            continue

        # --- /skill 命令：查看/注入漏洞知识 ---
        if line == "/skill" or line.startswith("/skill "):
            parts = line.split()
            if len(parts) == 1:
                vulns = skill.list_vulns()
                print(skill.summary() if vulns else "[skill] 还没有任何漏洞知识（skills/ 为空）")
                continue
            vuln = parts[1]
            content = skill.load_skill(vuln)
            if not content:
                print(f"[skill] 没有 {vuln} 的知识")
                continue
            print(f"[skill] 已加载 {vuln} 知识（{len(content)} 字符），注入上下文")
            client.messages.append({"role": "user", "content": f"[skill/{vuln}] 漏洞知识：\n{content}"})
            continue

        # --- /memory 命令：三层记忆读写 ---
        if line == "/memory" or line.startswith("/memory "):
            if line == "/memory":
                long_mem = memory.load_long_memory() or "(空)"
                proj = memory.load_project() or "(空)"
                print("=== 长记忆（永久）===\n" + long_mem)
                print("\n=== 当前项目（中记忆）===\n" + proj)
                continue
            _, _, rest = line.partition(" ")
            if rest.startswith("pref "):
                memory.add_preference(rest[5:])
                print("已记入长记忆偏好。")
            elif rest.startswith("project "):
                memory.save_project(rest[8:])
                print("已写入当前项目状态。")
            elif rest == "reset-project":
                memory.reset_project()
                print("中记忆已清空（切换新项目）。")
            else:
                print("用法：/memory pref <text> | /memory project <text> | /memory reset-project")
            continue

        # --- /cdp 命令：手动查看 Chrome 页面 ---
        if line.startswith("/cdp"):
            from .cdp import CDPError
            cdp = ensure_cdp_client()
            if cdp is None:
                print("[cdp] CDP 未启动，自动拉起失败")
                print("      手动：Windows/WSL → cdp_tools/cdp_launcher.exe")
                print("            Linux/Mac   → chrome --remote-debugging-port=9222")
                continue
            parts = line.split()
            cmd = parts[1] if len(parts) > 1 else "list"

            if cmd in ("read", "html"):
                idx = int(parts[2]) if len(parts) > 2 else 0
                tabs = cdp.list_tabs()
                if not tabs:
                    print("[cdp] 没有页面 tab")
                    continue
                if not (0 <= idx < len(tabs)):
                    print(f"[cdp] 序号 {idx} 超出范围（0-{len(tabs)-1}）")
                    continue
                tab = tabs[idx]
                try:
                    content = cdp.read_page_text(tab) if cmd == "read" else cdp.read_page_html(tab)
                except CDPError as e:
                    print(f"[cdp] {e}")
                    continue
                label = "可见文本" if cmd == "read" else "DOM HTML"
                print(f"\n=== [{tab['title']}] {label}（{len(content)} 字符，显示前 3000）===\n{content[:3000]}\n")
                client.messages.append({"role": "user", "content": f"[工具/Chrome] 页面「{tab['title']}」的{label}：\n{content[:4000]}"})
                continue

            tabs = cdp.list_tabs()
            if not tabs:
                print("[cdp] 没有页面 tab（确认 Chrome 带 --remote-debugging-port 启动）")
                continue
            summary = "用户当前 Chrome 打开的页面：\n" + "\n".join(
                f"- {i}: {t['title']}  |  {t['url']}" for i, t in enumerate(tabs)
            )
            print(f"\n{summary}\n")
            client.messages.append({"role": "user", "content": f"[工具/Chrome] {summary}"})
            continue

        # --- 正常对话 + function calling tool loop ---
        try:
            resp = client.chat(line, tools=tools)
        except LLMError as e:
            print(f"[错误] {e}")
            continue

        while resp.get("type") == "tool_calls":
            results = []
            for tc in resp["tool_calls"]:
                fn = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                print(f"  [tool] {fn}({json.dumps(args, ensure_ascii=False)})")
                result = execute_tool(fn, args)
                results.append((tc["id"], fn, result))
            try:
                resp = client.submit_tool_results(results, tools=tools)
            except LLMError as e:
                print(f"[错误] {e}")
                resp = {"type": "text", "content": ""}
                break

        if resp.get("type") == "text":
            print(f"\nHackMate> {resp['content']}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
