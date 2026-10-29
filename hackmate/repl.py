"""主线程 REPL —— 对话 tool-loop + 命令，慢活交给后台 Job。

v2 相对 v1 cli.py：
- execute_tool 的大 if 链收敛到 tools.dispatch（表驱动）。
- improve_skill 走后台 Job，主循环不再被 18–45 分钟判分阻塞。
- 新命令 /jobs /job N /cancel N；每轮 prompt 前冒泡已完成的后台任务。
"""

import os
import sys
import json
import argparse
from pathlib import Path

from .config import load_config, PRESET_PROVIDERS
from .llm import LLMClient, LLMError
from .jobs import JobManager
from .tools import ToolContext, schemas, dispatch, discover_mcp
from . import memory, skill, log

BANNER = "HackMate v2 — AI 渗透情报副驾驶 (CLI)"

# 打靶动作集合：这些工具一旦被调用，说明 LLM 开始对靶场动手，此时程序强制注入 skill 知识
# （不依赖 LLM 自觉调 load_skill —— 历史上它 0 次调用，导致打靶时用错参数名）。
_BATTLE_TOOLS = {"navigate", "open_new_tab", "verify_xss", "find_xss_entries"}

HELP = """命令:
  /help         显示本帮助
  /clear        清空上下文（保留 system prompt）
  /stop         停止当前任务（清空上下文，回到干净对话）
  /cdp          查看当前 Chrome 打开的页面（带序号，注入上下文）
  /cdp read N   读第 N 个页面的可见文本
  /web          打开 Web 图形工作台（行动记录 / 对话 / 工具箱）
  /guide        AI 引导：读当前关 → 生成步骤 → 调试 Chrome 里光标带你一步步学
  /goal <目标>  设置自主目标，自动推进直到完成或卡住（如 /goal 打通 xss-labs level1-20）
  /model              弹出所有 LLM 供应商（含预设 model）
  /model <名称或编号>  切换供应商（如 /model 2 或 /model openai）
  /model <名称> <model>  切换 + 指定任意模型（如 /model openai gpt-5.5）
  /model <名称> <key>  配 key 并切换（sk- 开头识别为 key）
  /skill        列出可用漏洞知识（skills/）
  /memory       查看长记忆 + 当前项目状态
  /log          查看最近 10 条关键结果（skill/漏洞/case）
  /log steps    查看最近 20 条关键步骤 + 后台任务
  /jobs         列出后台任务（判分 / skill 改进）
  /job N        看第 N 个后台任务详情/进度
  /cancel N     中断第 N 个后台任务
  /exit         退出（也可用 exit / quit / Ctrl+C）
  其它任意输入发给 LLM（可自动调用浏览器/skill/eval 工具）
"""


def _enable_ansi():
    """Win10/11 控制台默认不开 VT 处理，Python 吐 ANSI 会变乱码。启动时开一次。"""
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            # STD_OUTPUT_HANDLE=-11；mode 7 = PROCESSED_OUTPUT|WRAP_AT_EOL|VIRTUAL_TERMINAL_PROCESSING
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


_ANSI = {"reset": "\033[0m", "dim": "\033[2m", "red": "\033[31m", "green": "\033[32m",
         "yellow": "\033[33m", "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m"}


def _c(t, color):
    """上色。非终端（重定向到文件/管道）或设了 NO_COLOR → 退化成无色，避免转义垃圾。"""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return t
    return f"{_ANSI.get(color, '')}{t}{_ANSI['reset']}"


def _yellow(t):
    return _c(t, "yellow")


def _render_tool(fn, args, result):
    """把一次工具调用压成一行、按类别上色。关键步骤高亮，侦察类暗色。"""
    url = args.get("url", "")
    rs = str(result)
    if fn == "verify_xss":
        status = ""
        try:
            status = json.loads(rs).get("status", "")
        except Exception:
            pass
        if status == "CONFIRMED":
            return _c(f"  ✓ 验证 CONFIRMED  {url}", "green")
        if status == "INCONCLUSIVE":
            return _c(f"  ? 验证 未触发    {url}", "yellow")
        if status == "NOT_CONFIRMED":
            return _c(f"  ✗ 验证 未成立    {url}", "red")
        return _c(f"  · 验证 {rs[:40]}  {url}", "dim")
    if fn == "save_case":
        return _c(f"  ✎ 记录 case [{args.get('vuln','')}] {rs}", "green")
    if fn == "run_tool":
        return _c(f"  ⚙ run_tool {args.get('tool','')} {args.get('args','')}".rstrip(), "magenta")
    if fn == "search_cve":
        return _c(f"  🔍 search_cve {args.get('keyword', args.get('component',''))}", "magenta")
    if fn == "improve_skill":
        return _c(f"  ⚙ 提交 skill 优化 '{args.get('vuln','')}/{args.get('variant','')}'（后台 Job）", "magenta")
    if fn == "open_new_tab":
        return _c(f"  ↗ 打开/复用测试页 {url}".rstrip(), "cyan")
    if fn == "navigate":
        return _c(f"  → 导航 {url}", "cyan")
    if fn == "save_project":
        return _c("  · 存进度", "dim")
    # 其余侦察/操作类：暗色一行
    hint = url or args.get("selector", "") or args.get("vuln", "")
    _names = {"find_xss_entries": "侦察注入点", "read_page_text": "读页面文本",
              "list_tabs": "列标签", "fill_form": "填表单",
              "click": "点击", "load_skill": "读 skill"}
    return _c(f"  · {_names.get(fn, fn)} {hint}".rstrip(), "dim")


# 成功 exploit 五段报告的字段配色
_REPORT_FIELDS = {"目标URL": "cyan", "测试parameter": "cyan", "注入payload": "green",
                  "原理": "magenta", "流程": "magenta", "CVSS": "red"}


def _colorize_report(text):
    """给 HackMate 文本里的 exploit 五段字段标签上色；其余行原样不动。"""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    out = []
    for line in text.split("\n"):
        s = line.lstrip()
        indent = line[:len(line) - len(s)]
        hit = False
        for label, color in _REPORT_FIELDS.items():
            for sep in ("：", ":"):
                if s.startswith(label + sep):
                    rest = s[len(label + sep):]
                    # payload / CVSS 整行高亮（含值），其余只给标签上色
                    whole_line = label in ("注入payload", "CVSS")
                    body = f"{label}{sep}{rest}" if whole_line else f"{label}{sep}"
                    tail = "" if whole_line else rest
                    out.append(indent + _c(body, color) + tail)
                    hit = True
                    break
            if hit:
                break
        if not hit:
            out.append(line)
    return "\n".join(out)


def build_system_prompt(cfg):
    parts = []
    sp = memory.load_system_prompt()
    parts.append(sp if sp else cfg["system_prompt"])
    prefs = memory.load_preferences()
    if prefs:
        parts.append("## 用户偏好\n" + prefs)
    proj = memory.load_project()
    if proj:
        parts.append("## 当前项目状态（中记忆，重启后保留）\n" + proj)
    steps = log.format_steps(20)
    if steps and "还没有任何" not in steps:
        parts.append("## 最近执行记录（历史证据；不能据此推断当前目标或任务仍在执行）\n" + steps)
    sk = skill.summary()
    if sk:
        parts.append(sk + "\n（⚠️ 打关前必须先 load_skill 读完整知识，规则正文不在此摘要里）")
    return "\n\n".join(parts)


def _surface_jobs(jobs, client):
    """冒泡已完成的后台任务：打印给用户，并把结果作为一条上下文告知 LLM。"""
    for j in jobs.drain_finished():
        print(_yellow(f"\n[后台任务 #{j.id}] {j.summary()}\n"))
        client.messages.append({
            "role": "user",
            "content": f"[系统通知] 后台任务 #{j.id}（{j.title}）{j.status}：{j.result or j.error}",
        })


def _run_tool_loop(client, tool_schemas, ctx, resp, loaded_skill, max_iters=None):
    """处理一轮 tool loop：dispatch 工具 + 附加 skill + submit，直到 LLM 返回 text。

    打靶动作时程序强制把 skill 知识附加到工具结果（作为 tool 消息的一部分，不插入
    独立消息，避免破坏 assistant tool_calls → tool 消息的配对结构）。
    max_iters 非 None 时限制最大工具轮数（供 /goal 防失控），超限主动收尾。
    返回 (resp, loaded_skill)。不捕获 KeyboardInterrupt，交给调用方。
    """
    iters = 0
    while resp.get("type") == "tool_calls":
        iters += 1
        if max_iters is not None and iters > max_iters:
            print(_yellow(f"[goal] 已 {max_iters} 轮工具调用仍未收敛，主动收尾"))
            client.messages.append({
                "role": "user",
                "content": "[系统] 已达最大工具轮数，请立即收尾：完成则报 exploit结果，否则说明卡点。",
            })
            resp = client._dispatch(client._post(tools=tool_schemas))
            break
        results = []
        for tc in resp["tool_calls"]:
            fn = tc["function"]["name"]
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            result = dispatch(fn, args, ctx)
            if fn in _BATTLE_TOOLS and not loaded_skill:
                parts = []
                for v in skill.list_vulns():
                    c = skill.load_overview(v)
                    if c:
                        parts.append(f"[系统已注入 '{v}' overview（总纲）。详细 variant 请按需 load_skill(vuln, variant) 读，别一次读全部]\n{c}")
                if parts:
                    result = result + "\n\n" + "\n\n".join(parts)
                    loaded_skill = True
            log.record_step(fn, args, result)
            print(_render_tool(fn, args, result))
            results.append((tc["id"], fn, result))
        try:
            resp = client.submit_tool_results(results, tools=tool_schemas)
            client.compact()
        except LLMError as e:
            print(_c(f"[错误] {e}", "red"))
            resp = {"type": "text", "content": ""}
            break
    return resp, loaded_skill


def chat_loop():
    cfg = load_config()

    if not cfg["api_key"]:
        print("首次运行，未检测到 API key。")
        try:
            key = input("请粘贴你的 API key（sk-...）: ").strip()
        except EOFError:
            print("无输入（非交互环境），请在 .env 填 HACKMATE_API_KEY 后重跑。")
            return 1
        if not key:
            print("未输入 key，退出。")
            return 1
        env_path = Path(".env")
        if env_path.exists():
            print(f"{env_path} 已存在，请手动编辑填入 HACKMATE_API_KEY=sk-xxx。")
            return 1
        env_path.write_text(f"HACKMATE_API_KEY={key}\n", encoding="utf-8")
        print(f"已写入 {env_path}，重新加载配置...")
        cfg = load_config()
        if not cfg["api_key"]:
            print("配置加载失败，请检查 .env。")
            return 1

    system_prompt = build_system_prompt(cfg)
    client = LLMClient(cfg["base_url"], cfg["api_key"], cfg["model"], system_prompt)
    jobs = JobManager()
    mcp_conn, mcp_tools = discover_mcp(cfg)  # 连外部 MCP 服务器，动态注册工具
    tool_schemas = schemas()
    loaded_skill = False  # 本会话是否已自动加载过 skill 知识（打靶前程序强制注入）

    try:
        import readline  # noqa: F401  历史/行编辑，Windows 原生可能没有
    except ImportError:
        pass

    _cdp = {"client": None}

    def ensure_cdp_client():
        from .cdp import ensure_cdp
        if _cdp["client"] is not None:
            try:
                _cdp["client"]._get_json("/json/version")
                return _cdp["client"]
            except Exception:
                _cdp["client"] = None
        _cdp["client"] = ensure_cdp(cfg["cdp_host"], int(cfg["cdp_port"]))
        return _cdp["client"]

    ctx = ToolContext(cfg, client, jobs, ensure_cdp_client)

    print(BANNER)
    print(f"模型: {cfg['model']}  |  端点: {cfg['base_url']}")
    print(f"已加载 {len(tool_schemas)} 个工具 | 可用漏洞知识: {', '.join(skill.list_vulns()) or '无'}")
    print("输入 /help 查看命令，直接输入文字开始对话。\n")

    while True:
        _surface_jobs(jobs, client)
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
        if line in ("/stop", "stop"):
            memory.mark_project_interrupted()
            log.record_task_interrupted()
            client.system_prompt = build_system_prompt(cfg)
            client.clear()
            print("[stop] 上一任务已标记为中止/未完成，上下文已清空（后台任务用 /cancel N 中断）")
            continue
        if line in ("/help", "help"):
            print(HELP)
            continue
        if line.startswith("/model"):
            parts = line.split()
            presets = PRESET_PROVIDERS
            configured = cfg.get("providers", {})
            cur = cfg.get("provider", "")
            if len(parts) == 1:
                print("LLM 供应商（/model <编号或名称> 切换）：")
                for i, (name, p) in enumerate(presets.items(), 1):
                    has_key = bool(configured.get(name, {}).get("api_key"))
                    mark = "  ← 当前" if name == cur else ""
                    kstate = "已配key" if has_key else "未配key"
                    compat = "" if p.get("compat", True) else "（非OpenAI兼容，需adapter）"
                    print(f"  [{i}] {name:<12} {p['desc']:<14} {p['model']:<28} {kstate}{compat}{mark}")
                print("切换 + 指定任意模型：/model <名称> [model]（如 /model openai gpt-5.5）")
                print("配 key：/model <名称> <api_key>（sk- 开头识别为 key）")
                continue
            name = parts[1]
            if name.isdigit():
                keys = list(presets.keys())
                idx = int(name) - 1
                if 0 <= idx < len(keys):
                    name = keys[idx]
                else:
                    print(f"编号 {parts[1]} 无效（共 {len(keys)} 个）")
                    continue
            if name not in presets:
                print(f"未知供应商 '{name}'。用 /model 看全部可用供应商")
                continue
            p = presets[name]
            if not p.get("compat", True):
                print(f"{name} 是非 OpenAI 兼容端点（{p['desc']}），需要单独 adapter，当前不支持直接切换")
                continue
            stored = configured.get(name, {})
            api_key = stored.get("api_key", "")
            model = stored.get("model", p["model"])
            extra = parts[2:]
            if extra:
                # 第一个参数：sk-/长串 → key；否则 → model（任意模型名，如 gpt-5.5）
                if extra[0].startswith("sk-") or extra[0].startswith("gsk_") or len(extra[0]) >= 30:
                    api_key = extra[0]
                    if len(extra) >= 2:
                        model = extra[1]
                else:
                    model = extra[0]
            if not api_key:
                print(f"{name}（{p['desc']}）未配 api_key。用 /model {name} <你的key> 配置，或改 config.json 的 providers")
                continue
            cfg.setdefault("providers", {})[name] = {
                "base_url": p["base_url"], "model": model, "api_key": api_key,
            }
            cfg["provider"] = name
            cfg["base_url"] = p["base_url"]
            cfg["model"] = model
            cfg["skill_model"] = model  # 打靶 / skill 改进用同一个 model
            cfg["api_key"] = api_key
            system_prompt = build_system_prompt(cfg)
            client = LLMClient(cfg["base_url"], cfg["api_key"], cfg["model"], system_prompt)
            ctx.base_client = client
            print(f"已切换到 {name}（{model} @ {p['base_url']}），上下文已清空")
            continue
        if line == "/skill":
            vulns = skill.list_vulns()
            print(skill.summary() if vulns else "[skill] 还没有任何漏洞知识（skills/ 为空）")
            continue
        if line == "/memory":
            print("=== 用户偏好（长记忆）===\n" + (memory.load_preferences() or "(空)"))
            print("\n=== 当前项目（中记忆）===\n" + (memory.load_project() or "(空)"))
            continue
        if line == "/log":
            print(log.format_recent(10))
            continue
        if line == "/log steps":
            print(log.format_steps(20))
            continue
        if line == "/web":
            try:
                from .webui import open_ui
                url, opened = open_ui()
                if opened:
                    print(_c(f"[web] 已在浏览器打开工作台：{url}", "green"))
                else:
                    print(_yellow(f"[web] 工作台已启动：{url}（请复制到浏览器打开）"))
            except Exception as e:
                print(_c(f"[web] 无法启动工作台：{e}", "red"))
            continue
        if line == "/jobs":
            js = jobs.list_jobs()
            print("\n".join(j.summary() for j in js) if js else "暂无后台任务")
            continue
        if line.startswith("/job "):
            try:
                jid = int(line.split()[1])
            except (IndexError, ValueError):
                print("用法：/job N")
                continue
            j = jobs.get(jid)
            print(j.summary() if j else f"没有任务 #{jid}")
            continue
        if line.startswith("/cancel "):
            try:
                jid = int(line.split()[1])
            except (IndexError, ValueError):
                print("用法：/cancel N")
                continue
            print(f"已请求中断 #{jid}" if jobs.cancel(jid) else f"无法中断 #{jid}（不存在或已结束）")
            continue
        if line == "/guide":
            _handle_guide(ensure_cdp_client, client)
            continue
        if line.startswith("/cdp"):
            _handle_cdp(line, ensure_cdp_client, client)
            continue
        if line.startswith("/goal"):
            goal = line[len("/goal"):].strip()
            if not goal:
                print("用法：/goal <目标>，如 /goal 打通 xss-labs level1-20")
                continue
            prompt = (f"[目标] {goal}\n"
                      f"请自主完成这个目标，直到完成或无法继续为止。\n"
                      f"- 把目标拆成子步骤，按合理顺序逐个推进，完成一个再进下一个。\n"
                      f"- 卡住时深入分析根因，不要轻易放弃或偏离到无关任务。\n"
                      f"- 完成给出结果总结；无法继续时说明卡在哪、为什么。")
            try:
                resp = client.chat(prompt, tools=tool_schemas)
                resp, loaded_skill = _run_tool_loop(
                    client, tool_schemas, ctx, resp, loaded_skill, max_iters=300)
            except KeyboardInterrupt:
                memory.mark_project_interrupted()
                log.record_task_interrupted()
                client.system_prompt = build_system_prompt(cfg)
                client.clear()
                print("\n[已停止] 目标执行已中止，上下文已清空。")
                continue
            except LLMError as e:
                print(_c(f"[错误] {e}", "red"))
                continue
            if resp.get("type") == "text" and resp["content"]:
                print(f"\n{_c('HackMate>', 'blue')} {_colorize_report(resp['content'])}\n")
            continue

        # --- 正常对话 + tool loop ---
        try:
            resp = client.chat(line, tools=tool_schemas)
        except KeyboardInterrupt:
            memory.mark_project_interrupted()
            log.record_task_interrupted()
            client.system_prompt = build_system_prompt(cfg)
            client.clear()
            print("\n[已停止] 当前任务已标记为中止/未完成，上下文已清空。")
            continue
        except LLMError as e:
            print(_c(f"[错误] {e}", "red"))
            print(_c("[提示] 上一步失败，上下文已保留——可直接重试或 /clear 重来", "dim"))
            continue

        try:
            resp, loaded_skill = _run_tool_loop(client, tool_schemas, ctx, resp, loaded_skill)
        except KeyboardInterrupt:
            memory.mark_project_interrupted()
            log.record_task_interrupted()
            client.system_prompt = build_system_prompt(cfg)
            client.clear()
            print("\n[已停止] 当前任务已标记为中止/未完成，上下文已清空。")
            continue

        if resp.get("type") == "text" and resp["content"]:
            print(f"\n{_c('HackMate>', 'blue')} {_colorize_report(resp['content'])}\n")

    return 0


def _handle_cdp(line, ensure_cdp_client, client):
    from .cdp import CDPError
    cdp = ensure_cdp_client()
    if cdp is None:
        print("[cdp] CDP 未启动，自动拉起失败")
        print("      Windows/WSL → tools/cdp/launcher/cdp_launcher.exe")
        print("      Linux/Mac   → chrome --remote-debugging-port=9222")
        return
    parts = line.split()
    cmd = parts[1] if len(parts) > 1 else "list"
    if cmd == "read":
        idx = int(parts[2]) if len(parts) > 2 else 0
        tabs = cdp.list_tabs()
        if not tabs:
            print("[cdp] 没有页面 tab")
            return
        if not (0 <= idx < len(tabs)):
            print(f"[cdp] 序号 {idx} 超出范围（0-{len(tabs)-1}）")
            return
        tab = tabs[idx]
        try:
            content = cdp.read_page_text(tab)
        except CDPError as e:
            print(f"[cdp] {e}")
            return
        print(f"\n=== [{tab['title']}] 可见文本（{len(content)} 字符，前 3000）===\n{content[:3000]}\n")
        client.messages.append({"role": "user",
                                "content": f"[工具/Chrome] 页面「{tab['title']}」可见文本：\n{content[:4000]}"})
        return
    tabs = cdp.list_tabs()
    if not tabs:
        print("[cdp] 没有页面 tab（确认 Chrome 带 --remote-debugging-port 启动）")
        return
    summary = "用户当前 Chrome 打开的页面：\n" + "\n".join(
        f"- {i}: {t['title']}  |  {t['url']}" for i, t in enumerate(tabs))
    print(f"\n{summary}\n")
    client.messages.append({"role": "user", "content": f"[工具/Chrome] {summary}"})


_GUIDE_SYS = (
    "你是靶场教学引导生成器。根据给定的当前关页面信息，产出 4-6 步引导，帮助用户理解并一步步"
    "利用这一关的漏洞。引导是【手动推进】的：用户看完一步点「下一步」才到下一步，所以步骤要有清晰的递进顺序。\n"
    "只输出一个 JSON 数组，每项形如 "
    '{"selector":"CSS选择器","text":"一句通俗中文说明","code":false}。\n'
    "规则：\n"
    "- selector 必须指向页面上真实存在的元素，优先用给出的输入框 name/id（如 input[name=\"keyword\"]），"
    "反射点/正文可用 h2 或 body。\n"
    "- 【必须有一步指出源代码/反射点】：把 selector 指向用户输入在页面上出现的那个元素（反射点），并设 "
    '"code":true —— 这样气泡会展示该元素的真实 HTML，让用户亲眼看到自己的输入落在哪段代码里。'
    "若页面有 View Source / 查看源码 的按钮或链接，也可用一步指向它。\n"
    "- 最后一步 selector 用 body、鼓励用户动手尝试。\n"
    "- text 通俗易懂、讲清“为什么”，不堆术语。\n"
    "- 这是 XSS（跨站脚本）靶场：引导只围绕 XSS 注入与过滤绕过，目标是让页面弹出 alert/confirm；"
    "绝不要讲 SQL 注入、闭合 SQL 语句等其他漏洞。payload 示例要用 XSS 向量（如 <script>、\"> 闭合、事件处理器）。\n"
    "只输出 JSON，不要解释、不要代码块标记。"
)


def _parse_steps(raw):
    import re
    t = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
    m = re.search(r"\[.*\]", t, re.S)
    if m:
        t = m.group(0)
    try:
        data = json.loads(t)
    except Exception:
        return []
    out = []
    for s in data if isinstance(data, list) else []:
        if not isinstance(s, dict):
            continue
        sel = s.get("selector") or s.get("sel") or "body"
        txt = str(s.get("text", "")).strip()
        code = bool(s.get("code") or s.get("showcode"))
        if txt:
            out.append([sel, txt, code])
    return out[:8]


def _handle_guide(ensure_cdp_client, client):
    from .cdp import CDPError
    cdp = ensure_cdp_client()
    if cdp is None:
        print(_c("[guide] CDP 未就绪（先 /cdp 把调试 Chrome 拉起，并打开要学的靶场页面）", "red"))
        return
    try:
        tabs = cdp.list_tabs()
        if not tabs:
            print(_c("[guide] 没有页面 tab", "red"))
            return
        tab = cdp.ensure_test_tab(initial_url=tabs[0].get("url") or "about:blank")
        entries = cdp.find_xss_entries(test_tab=True)
        text = cdp.read_page_text(test_tab=True)[:1200]
        html = cdp.read_page_html(test_tab=True)[:2500]
    except CDPError as e:
        print(_c(f"[guide] 读取页面失败: {e}", "red"))
        return
    print(_c(f"[guide] 正在分析当前页面「{tab.get('title', '')}」并生成引导...", "cyan"))
    gen = client.clone(system_prompt=_GUIDE_SYS)
    prompt = (f"当前关页面信息：\n注入点/表单：{entries}\n\n可见文本（节选）：\n{text}\n\n"
              f"HTML 源码（节选，用于定位反射点/源码按钮的 CSS 选择器）：\n{html}\n\n"
              "请产出引导步骤 JSON 数组。")
    try:
        raw = gen.ask(prompt)
    except LLMError as e:
        print(_c(f"[guide] 生成引导失败: {e}", "red"))
        return
    steps = _parse_steps(raw)
    if not steps:
        steps = [["input", "① 这是输入点：页面会接收你输入的内容", False],
                 ["body", "② 你的输入会原样出现在页面 HTML 里（反射点）——这是关键", True],
                 ["body", "③ 没有过滤时，输入 <script>alert(1)</script> 会被当代码执行——弹窗=XSS 成立", False]]
        print(_c("[guide] 未能解析 AI 步骤，用通用引导兜底", "yellow"))
    print(_c(f"[guide] 生成 {len(steps)} 步（在调试 Chrome 里点「下一步」逐步推进）：", "cyan"))
    for i, s in enumerate(steps, 1):
        tag = " [含源码]" if len(s) > 2 and s[2] else ""
        print(_c(f"  {i}. {s[1]}{tag}", "dim"))
    try:
        cdp.guide_tour(steps, test_tab=True)
    except CDPError as e:
        print(_c(f"[guide] 注入失败: {e}", "red"))


def cmd_skill():
    vulns = skill.list_vulns()
    print(skill.summary() if vulns else "还没有任何漏洞知识（skills/ 为空）")
    return 0


def cmd_cdp(args):
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
        for i, t in enumerate(tabs):
            print(f"- {i}: {t['title']}  |  {t['url']}")
    return 0


def cmd_memory():
    print("=== 用户偏好（长记忆）===\n" + (memory.load_preferences() or "(空)"))
    print("\n=== 当前项目（中记忆）===\n" + (memory.load_project() or "(空)"))
    return 0


def cmd_log():
    print(log.format_recent(10))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hackmate", description="HackMate v2 — AI 渗透情报副驾驶")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("chat", help="进入交互式对话（默认）")
    sub.add_parser("skill", help="列出漏洞知识")
    p_cdp = sub.add_parser("cdp", help="列出 / 读 Chrome 页面")
    p_cdp.add_argument("action", nargs="?", choices=["read"])
    p_cdp.add_argument("index", nargs="?", type=int, default=0)
    sub.add_parser("memory", help="查看长记忆 + 当前项目")
    sub.add_parser("log", help="查看最近关键事件")
    p_web = sub.add_parser("web", help="启动本机 Web 工作台")
    p_web.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"])
    p_web.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    _enable_ansi()

    if args.cmd == "skill":
        return cmd_skill()
    if args.cmd == "cdp":
        return cmd_cdp(args)
    if args.cmd == "memory":
        return cmd_memory()
    if args.cmd == "log":
        return cmd_log()
    if args.cmd == "web":
        from .webui import serve
        return serve(args.host, args.port)
    return chat_loop()


if __name__ == "__main__":
    sys.exit(main())
