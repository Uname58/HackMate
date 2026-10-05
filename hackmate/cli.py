"""HackMate CLI —— 与 LLM 对话的最小入口（支持 function calling 调用 CDP 工具）。

启动：python chat.py（在 HackMate 根目录）
"""

import sys
import json

from .config import load_config
from .llm import LLMClient, LLMError

BANNER = "HackMate v0.1 — AI 渗透情报副驾驶 (CLI)"

HELP = """命令:
  /help        显示本帮助
  /clear       清空上下文（保留 system prompt）
  /cdp         查看当前 Chrome 打开的页面（带序号，注入上下文）
  /cdp read N  读第 N 个页面的可见文本
  /cdp html N  读第 N 个页面的 DOM HTML
  /exit        退出（也可用 exit / quit / Ctrl+C）
  其它任意输入都会发给 LLM 对话（LLM 可自动调用浏览器工具）
"""

# LLM 可调用的浏览器工具（function calling schema）
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_tabs",
            "description": "列出 Chrome 当前打开的所有页面（标题和 URL）",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "open_new_tab",
            "description": "在 Chrome 里开一个新标签页并导航到指定 URL（空白页用 about:blank）",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "要打开的 URL，默认 about:blank"}
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_page_text",
            "description": "读第 index 个页面的可见文本内容",
            "parameters": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "description": "页面序号，从 0 开始"}
                },
                "required": ["index"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "navigate",
            "description": "导航第 index 个页面到指定 URL",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL"},
                    "index": {"type": "integer", "description": "页面序号，默认 0"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fill_form",
            "description": "在第 index 个页面填表单字段（CSS selector + 值，React/Vue 兼容）",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector，如 #username"},
                    "value": {"type": "string", "description": "要填的值"},
                    "index": {"type": "integer", "description": "页面序号，默认 0"},
                },
                "required": ["selector", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "click",
            "description": "点击第 index 个页面上的元素（CSS selector）",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector"},
                    "index": {"type": "integer", "description": "页面序号，默认 0"},
                },
                "required": ["selector"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_xss_entries",
            "description": "扫描第 index 个页面的 XSS 注入点候选（输入框、表单、URL 参数、带参数的链接）",
            "parameters": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "description": "页面序号，默认 0"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_xss",
            "description": "黑盒验证 XSS：导航到带 payload 的完整 URL，检测 alert 弹窗是否触发（触发=JS 执行=XSS 成立）",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "带 XSS payload 的完整 URL"},
                    "index": {"type": "integer", "description": "页面序号，默认 0"},
                },
                "required": ["url"],
            },
        },
    },
]


def main():
    cfg = load_config()

    if not cfg["api_key"]:
        print("首次运行，未检测到 API key。")
        key = input("请粘贴你的 API key（sk-...）: ").strip()
        if not key:
            print("未输入 key，退出。")
            return 1
        from pathlib import Path
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

    client = LLMClient(cfg["base_url"], cfg["api_key"], cfg["model"], cfg["system_prompt"])

    print(BANNER)
    print(f"模型: {cfg['model']}  |  端点: {cfg['base_url']}")
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

        # 正常对话 + function calling tool loop
        try:
            resp = client.chat(line, tools=TOOLS)
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
                resp = client.submit_tool_results(results, tools=TOOLS)
            except LLMError as e:
                print(f"[错误] {e}")
                resp = {"type": "text", "content": ""}
                break

        if resp.get("type") == "text":
            print(f"\nHackMate> {resp['content']}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
