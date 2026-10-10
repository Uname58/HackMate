"""HackMate CLI —— AI 渗透副驾驶，三支柱闭环（memory / skill / tool）。

启动：python chat.py（在 HackMate 根目录）
"""

import sys
import json
import argparse
from pathlib import Path

from .config import load_config, app_root
from .llm import LLMClient, LLMError
from . import memory, skill

BASE_DIR = app_root()  # HackMate 根目录
TOOLS_DIR = BASE_DIR / "tools"

BANNER = "HackMate v0.2 — AI 渗透情报副驾驶 (CLI)"


def _yellow(text):
    """终端黄色文字（ANSI 转义）。"""
    return f"\033[33m{text}\033[0m"

HELP = """命令:
  /help        显示本帮助
  /clear       清空上下文（保留 system prompt）
  /cdp         查看当前 Chrome 打开的页面（带序号，注入上下文）
  /cdp read N  读第 N 个页面的可见文本
  /skill       列出可用的漏洞知识（skills/）
  /memory      查看长记忆 + 当前项目状态
  /exit        退出（也可用 exit / quit / Ctrl+C）
  其它任意输入都会发给 LLM 对话（LLM 可自动调用浏览器/skill 工具）
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


def build_system_prompt(cfg):
    """闭环起点：长记忆（system prompt + 偏好）+ 中记忆（项目状态）+ skill 目录摘要 拼成 system prompt。"""
    parts = []
    sp = memory.load_system_prompt()
    parts.append(sp if sp else cfg["system_prompt"])
    prefs = memory.load_preferences()
    if prefs:
        parts.append("## 用户偏好\n" + prefs)
    proj = memory.load_project()
    if proj:
        parts.append("## 当前项目状态（中记忆，重启后保留）\n" + proj)
    sk = skill.summary()
    if sk:
        parts.append(sk + "\n（用 /skill <vuln> 查看某类漏洞的完整知识）")
    return "\n\n".join(parts)


def cmd_skill():
    """列出漏洞知识。"""
    vulns = skill.list_vulns()
    print(skill.summary() if vulns else "还没有任何漏洞知识（skills/ 为空）")
    return 0


def cmd_cdp(args):
    """列出 / 读 Chrome 页面。"""
    from .cdp import resolve_cdp_host, ensure_cdp
    cfg = load_config()
    host = resolve_cdp_host(cfg["cdp_host"])
    c = ensure_cdp(host, int(cfg["cdp_port"]))
    if c is None:
        print("[cdp] CDP 未就绪")
        return 1
    tabs = c.list_tabs()
    if args.action == "read":
        if not (0 <= args.index < len(tabs)):
            print(f"[cdp] 序号 {args.index} 超出范围（0-{len(tabs)-1}）")
            return 1
        print(c.read_page_text(tabs[args.index]))
    else:
        if not tabs:
            print("[cdp] 没有页面 tab")
            return 0
        for i, t in enumerate(tabs):
            print(f"- {i}: {t['title']}  |  {t['url']}")
    return 0


def cmd_memory():
    """查看偏好 + 当前项目。"""
    prefs = memory.load_preferences() or "(空)"
    proj = memory.load_project() or "(空)"
    print("=== 用户偏好（长记忆）===\n" + prefs)
    print("\n=== 当前项目（中记忆）===\n" + proj)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hackmate", description="HackMate — AI 渗透情报副驾驶")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("chat", help="进入交互式对话（默认）")
    sub.add_parser("skill", help="列出漏洞知识")
    p_cdp = sub.add_parser("cdp", help="列出 / 读 Chrome 页面")
    p_cdp.add_argument("action", nargs="?", choices=["read"], help="read 读第 index 页")
    p_cdp.add_argument("index", nargs="?", type=int, default=0, help="页面序号")
    sub.add_parser("memory", help="查看长记忆 + 当前项目")
    args = parser.parse_args(argv)

    if args.cmd == "skill":
        return cmd_skill()
    if args.cmd == "cdp":
        return cmd_cdp(args)
    if args.cmd == "memory":
        return cmd_memory()
    return chat_loop()


def chat_loop():
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
        from .cdp import ensure_cdp
        # 缓存失效：CDP 可能已死（如用户关了 Chrome），检测不活则重新拉起
        if _cdp["client"] is not None:
            try:
                _cdp["client"]._get_json("/json/version")
                return _cdp["client"]
            except Exception:
                _cdp["client"] = None
        _cdp["client"] = ensure_cdp(cfg["cdp_host"], int(cfg["cdp_port"]))
        return _cdp["client"]

    def execute_tool(name, args):
        """执行 LLM 请求的工具，返回结果字符串。"""
        # 不依赖 CDP 的工具先处理
        if name == "save_project":
            memory.save_project(args.get("note", ""))
            return "中记忆已保存"
        if name == "save_case":
            import time as _t
            from . import eval as ev
            vuln = args.get("vuln", "")
            case = {
                "id": f"auto-{_t.strftime('%Y%m%d%H%M%S')}",
                "input": args.get("input", ""),
                "expected": args.get("expected", ""),
                "grader": "contains",
                "keyword": args.get("keyword", ""),
            }
            return ev.append_case(vuln, "hidden", case)
        if name == "load_skill":
            content = skill.load_skill(args.get("vuln", ""))
            return content if content else "没有该漏洞的知识"
        if name == "improve_skill":
            from . import eval as ev
            vuln = args.get("vuln", "")
            variant = args.get("variant", "")
            vpath = skill.get_variant_path(vuln, variant)
            is_new = not vpath.exists()
            cases = ev.load_group(vuln, "regression")
            if not cases:
                return f"{vuln} 没有 regression case，无法 eval 判分"
            current = vpath.read_text(encoding="utf-8") if vpath.exists() else ""
            gen = LLMClient(cfg["base_url"], cfg["api_key"], cfg["model"],
                            "你是 HackMate 的 skill 改进器，只输出改进后的完整 skill 内容（markdown），不要任何解释或代码块标记。")
            prompt = (f"当前 {vuln}/{variant} 的 skill 内容：\n\n{current}\n\n"
                      f"请补充/修正漏洞知识，输出改进后的完整内容。")
            try:
                print(_yellow(f"生成 {vuln}/{variant} 候选 skill 中..."))
                candidate = gen.chat(prompt)["content"]
            except LLMError as e:
                return f"生成候选失败: {e}"
            print(_yellow(f"eval gate 判分中（{len(cases)} case × 2 轮，约 {len(cases)*2*2} 次 LLM 调用，稍等）..."))
            eval_client = LLMClient(cfg["base_url"], cfg["api_key"], cfg["model"], "")
            eval_fn = skill.make_skill_eval_fn(vuln, cases, eval_client)
            kept, before, after = skill.improve_skill(vuln, variant, candidate, eval_fn)
            if kept:
                if is_new:
                    print(_yellow(f'hackmate>！！！发现skill "{variant}"'))
                else:
                    print(_yellow(f'hackmate>！！！改进skill "{variant}"'))
            return f"eval gate：改进前 {before:.0%} → 改进后 {after:.0%}，" + ("已保留" if kept else "已回滚")
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

        # --- /skill 命令：列出漏洞知识 ---
        if line == "/skill":
            vulns = skill.list_vulns()
            print(skill.summary() if vulns else "[skill] 还没有任何漏洞知识（skills/ 为空）")
            continue

        # --- /memory 命令：查看记忆 ---
        if line == "/memory":
            prefs = memory.load_preferences() or "(空)"
            proj = memory.load_project() or "(空)"
            print("=== 用户偏好（长记忆）===\n" + prefs)
            print("\n=== 当前项目（中记忆）===\n" + proj)
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

            if cmd == "read":
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
                    content = cdp.read_page_text(tab)
                except CDPError as e:
                    print(f"[cdp] {e}")
                    continue
                print(f"\n=== [{tab['title']}] 可见文本（{len(content)} 字符，显示前 3000）===\n{content[:3000]}\n")
                client.messages.append({"role": "user", "content": f"[工具/Chrome] 页面「{tab['title']}」的可见文本：\n{content[:4000]}"})
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
