"""工具注册表 —— v2 表驱动，schema + handler 合一（单一真相源，无漂移）。

v1 把 schema.json 用 glob 单独加载、handler 塞在 cli.py 的大 if 链里，两头容易漂移。
v2 每个工具 = 一条注册项 {name, description, parameters, handler}，启动时自动生成给 LLM 的
function-calling 列表。新增工具只改这一处。

handler 签名：handler(args: dict, ctx: ToolContext) -> str
"""

import json
import time

from . import memory, skill, log
from . import eval as ev


class ToolContext:
    """工具执行上下文：配置 / 主 LLM / Job 管理器 / CDP 懒加载器。"""
    def __init__(self, cfg, base_client, jobs, get_cdp):
        self.cfg = cfg
        self.base_client = base_client
        self.jobs = jobs
        self.get_cdp = get_cdp  # callable() -> CDPClient | None


# ---- handlers ----
def _h_save_project(args, ctx):
    memory.save_project(args.get("note", ""))
    return "中记忆已保存"


def _h_save_case(args, ctx):
    vuln = args.get("vuln", "")
    case = {
        "id": f"auto-{time.strftime('%Y%m%d%H%M%S')}",
        "context": args.get("context", ""),
        "reference_payload": args.get("reference_payload", ""),
        "principle": args.get("principle", ""),
        "source": args.get("source", "auto"),
    }
    if args.get("verify_url"):
        case["verify_url"] = args["verify_url"]
    if args.get("evidence"):
        evidence = args["evidence"]
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except json.JSONDecodeError:
                evidence = None
        if isinstance(evidence, dict):
            case["evidence"] = evidence
    # 打过的靶场=训练材料，写 dev（improver 可见）；regression+hidden 是留出考卷，不经此写入
    result = ev.append_case(vuln, "dev", case)
    log.record("case", vuln=vuln, context=case["context"],
               reference_payload=case["reference_payload"])
    # 沉淀后自动触发 improve_skill：从新 case 提炼 skill 改进，经 eval gate 判分（涨保留/跌回滚）。
    # 程序强制（不依赖 LLM 自觉调 improve_skill —— 历史上 0 次调用导致闭环断裂）。
    variant = args.get("variant", "") or "reflection_xss"

    # 节流：已有 improve_skill 在跑/排队时不再叠加（避免判分任务堆积、gate 并发写同一 skill）
    if any(j.kind == "improve_skill" and j.status in ("queued", "running")
           for j in ctx.jobs.list_jobs()):
        return result + "（已有 skill 改进任务在跑，本次不自动叠加，稍后可手动 improve_skill）"

    def _run(job):
        try:
            cdp = ctx.get_cdp()
        except Exception:
            cdp = None
        return skill.run_improvement(job, ctx.cfg, ctx.base_client, vuln, variant, cdp=cdp)

    job = ctx.jobs.submit("improve_skill", _run, title=f"improve {vuln}/{variant}")
    return (result + f"；已自动提交后台改进任务 #{job.id}"
            f"（gate 判分后保留/回滚，/job {job.id} 看进度）")


def _h_load_skill(args, ctx):
    content = skill.load_skill(args.get("vuln", ""), args.get("variant"))
    return content if content else "没有该漏洞的知识（或该 variant 不存在）"


def _h_run_tool(args, ctx):
    """调用 vendor/ 里的白名单 CLI 工具（sqlmap/dalfox/commix...）。"""
    import subprocess, shlex
    from pathlib import Path
    vendor_dir = Path(__file__).resolve().parent.parent / "vendor"
    rp = vendor_dir / "tools.json"
    if not rp.exists():
        return "vendor/tools.json 不存在，工具清单未配置"
    try:
        registry = json.loads(rp.read_text(encoding="utf-8"))
    except Exception as e:
        return f"读 tools.json 失败：{e}"
    tool = args.get("tool", "")
    if tool not in registry:
        return f"未知工具 '{tool}'。可用：{', '.join(registry)}"
    t = registry[tool]
    if not t.get("ready", False):
        return f"工具 '{tool}' 未就绪：{t.get('note', '需配置依赖')}｜用途：{t.get('desc', '')}"
    try:
        cmd = shlex.split(t["entry"]) + shlex.split(args.get("args", ""))
    except ValueError as e:
        return f"参数解析失败：{e}"
    try:
        import os
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"  # Windows 原生 GBK 控制台编码不了 emoji/特殊字符
        # cwd：工具自己的目录（fuxploider 等用相对路径读 templates.json 等资源文件，必须在工具目录内跑）；
        # blindx 是包（python -m 导入），cwd 需在 vendor/（父目录）才能 import。
        tool_dir = vendor_dir / tool
        cwd = str(vendor_dir if tool == "blindx" else tool_dir)
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env=env, timeout=120)
        out = (r.stdout or "") + ("\n[stderr]\n" + r.stderr if r.stderr else "")
        if len(out) > 6000:
            out = out[:6000] + "\n…[输出截断]"
        return out.strip() or f"（无输出，退出码 {r.returncode}）"
    except subprocess.TimeoutExpired:
        return "（执行超时 120s，已终止）"
    except Exception as e:
        return f"（执行失败：{e}）"


def _h_run_shell(args, ctx):
    """执行 shell 命令（curl/管道/写文件/Python 脚本）。cwd 固定 tmp 目录，shell=True 让管道重定向生效。

    这是补「执行通路缺 shell」的关键：文件上传的 multipart POST、二次渲染的本地 GD diff、
    任意命令回显验证，都靠它。⚠️ 只用于打靶范围内的合法操作，别执行破坏性命令。
    """
    import subprocess
    import os
    from .config import app_root
    cmd = args.get("command", "")
    if not cmd:
        return "需要 command 参数"
    tmp = (app_root() / "tmp").resolve()
    tmp.mkdir(parents=True, exist_ok=True)
    proc = None
    try:
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        # Windows 上 shell=True 的子进程树不会被 timeout 终止（已知坑：cmd.exe 被 terminate 但
        # 它 spawn 的子进程仍持有 stdout/stderr 管道，subprocess 会永久阻塞）。
        # 用 CREATE_NEW_PROCESS_GROUP + taskkill /T 才能连根杀掉进程树。
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(cmd, shell=True, cwd=str(tmp), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                errors="replace", env=env, **kwargs)
        out, err = proc.communicate(timeout=120)
        text = (out or "") + ("\n[stderr]\n" + err if err else "")
        if len(text) > 6000:
            text = text[:6000] + "\n…[输出截断]"
        return text.strip() or f"（无输出，退出码 {proc.returncode}）"
    except subprocess.TimeoutExpired:
        if proc is not None:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                                   capture_output=True)
                else:
                    proc.kill()
                proc.communicate()
            except Exception:
                pass
        return "（执行超时 120s，已终止进程树）"
    except Exception as e:
        return f"（执行失败：{e}）"


def _h_race(args, ctx):
    """并发发 N 个请求（条件竞争抢窗口 / 爆破）。Python 多线程，非顺序调用。"""
    import threading
    import urllib.request
    import urllib.error
    import time
    from collections import Counter
    url = args.get("url", "")
    method = args.get("method", "GET").upper()
    try:
        count = int(args.get("count", 20))
    except (TypeError, ValueError):
        count = 20
    if not url:
        return "需要 url 参数"
    results = []
    lock = threading.Lock()

    def worker(i):
        t0 = time.time()
        try:
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=8) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:
            code = f"err:{str(e)[:30]}"
        with lock:
            results.append({"i": i, "status": str(code), "dt": round(time.time() - t0, 3)})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dist = Counter(r["status"] for r in results)
    return json.dumps({"count": count, "status_dist": dict(dist),
                       "sample": results[:5]}, ensure_ascii=False)


def _h_search_cve(args, ctx):
    """查 CVE：调 NVD API 按组件/关键词搜。限流约 5s/次，别频繁调用。"""
    import urllib.request, urllib.parse
    keyword = args.get("keyword") or args.get("component", "")
    if not keyword:
        return "需要 keyword 或 component 参数"
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
           + urllib.parse.quote(keyword) + "&resultsPerPage=10")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return f"（CVE 查询失败：{e}）"
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return f"未找到与 '{keyword}' 相关的 CVE"
    lines = [f"与 '{keyword}' 相关的 CVE（前 {len(vulns)} 条）："]
    for v in vulns:
        cve = v.get("cve", {})
        desc = (cve.get("descriptions", [{}])[0].get("value", "") or "")[:120]
        lines.append(f"- {cve.get('id', '?')}: {desc}")
    return "\n".join(lines)


def _h_improve_skill(args, ctx):
    vuln = args.get("vuln", "")
    variant = args.get("variant", "")

    def _run(job):
        # 接真 CDP：带 verify_url 的 case 判分走浏览器金标准（真弹窗才算过）；
        # CDP 不就绪或某题真验异常，grader 自动退回评委语义，不会误判。
        try:
            cdp = ctx.get_cdp()
        except Exception:
            cdp = None
        return skill.run_improvement(job, ctx.cfg, ctx.base_client, vuln, variant, cdp=cdp)

    job = ctx.jobs.submit("improve_skill", _run, title=f"improve {vuln}/{variant}")
    return (f"已提交后台改进任务 #{job.id}（判分+产候选+gate 在后台跑，"
            f"用 /job {job.id} 看进度、/cancel {job.id} 中断；可继续对话）")


# ---- CDP 工具 ----
def _cdp(ctx):
    c = ctx.get_cdp()
    if c is None:
        raise RuntimeError("CDP 未就绪，无法执行浏览器操作")
    return c


def _h_list_tabs(args, ctx):
    cdp = _cdp(ctx)
    tabs = cdp.list_tabs()
    result = []
    for i, tab in enumerate(tabs):
        try:
            active = cdp.is_tab_active(tab)
        except Exception:
            active = None
        result.append({"index": i, "title": tab["title"], "url": tab["url"],
                       "active": active})
    return json.dumps(result, ensure_ascii=False)


def _h_close_tab(args, ctx):
    """关闭指定 tab（index 或 id）。HackMate 专用测试标签拒绝关闭。"""
    cdp = _cdp(ctx)
    tabs = cdp.list_tabs()
    if "index" in args:
        index = args["index"]
        if not isinstance(index, int) or isinstance(index, bool) or not (0 <= index < len(tabs)):
            return f"标签序号无效: {index}（当前共 {len(tabs)} 个页面）"
        tab = tabs[index]
    elif "id" in args:
        tab = next((t for t in tabs if t["id"] == args["id"]), None)
        if tab is None:
            return f"未找到 id={args['id']} 的标签"
    else:
        return "需要 index 或 id 参数"
    closed = cdp.close_tab(tab["id"])
    if closed is False:
        return json.dumps({"closed": False, "reason": "HackMate 专用测试标签，拒绝关闭"}, ensure_ascii=False)
    return json.dumps({"closed": True, "title": tab["title"], "url": tab["url"]}, ensure_ascii=False)


def _h_open_new_tab(args, ctx):
    cdp = _cdp(ctx)
    tab = cdp.ensure_test_tab()
    url = args.get("url")
    if url:
        cdp.navigate(url, test_tab=True)
    return json.dumps({"test_tab": True, "url": url or tab.get("url", "")},
                      ensure_ascii=False)


def _h_read_page_text(args, ctx):
    c = _cdp(ctx)
    if "index" in args:
        tabs = c.list_tabs()
        index = args["index"]
        if not isinstance(index, int) or isinstance(index, bool) or not (0 <= index < len(tabs)):
            return f"标签序号无效: {index}（当前共 {len(tabs)} 个页面）"
        text = c.read_page_text(tab=tabs[index])
    else:
        text = c.read_page_text(test_tab=True)
    return text[:2000] if len(text) > 2000 else text


def _h_navigate(args, ctx):
    return _cdp(ctx).navigate(args.get("url", "about:blank"), test_tab=True)


def _h_fill_form(args, ctx):
    return _cdp(ctx).fill_form(args["selector"], args["value"], test_tab=True)


def _h_upload_file(args, ctx):
    return _cdp(ctx).upload_file(args["selector"], args["file_path"], test_tab=True)


def _h_write_file(args, ctx):
    """把文件写到 HackMate tmp 目录（造 polyglot 图片马等二进制文件用）。"""
    import base64
    from .config import app_root
    name = args.get("path", "")
    content_b64 = args.get("content_base64", "")
    if not name or not content_b64:
        return "需要 path 和 content_base64 参数"
    tmp = (app_root() / "tmp").resolve()
    tmp.mkdir(parents=True, exist_ok=True)
    target = (tmp / name).resolve()
    if not str(target).startswith(str(tmp)):
        return "非法路径：只允许写进 tmp 目录"
    try:
        data = base64.b64decode(content_b64)
    except Exception as e:
        return f"base64 解码失败：{e}"
    try:
        target.write_bytes(data)
    except Exception as e:
        return f"写文件失败：{e}"
    return f"已写 {len(data)} 字节到 {target}"


def _h_click(args, ctx):
    return _cdp(ctx).click(args["selector"], test_tab=True)


def _h_find_xss_entries(args, ctx):
    return _cdp(ctx).find_xss_entries(test_tab=True)


def _h_enumerate_site(args, ctx):
    return _cdp(ctx).enumerate_site(args["url"], test_tab=True)


def _h_verify_xss(args, ctx):
    result = _cdp(ctx).verify_xss(args["url"], test_tab=True)
    try:
        if json.loads(result).get("status") == "CONFIRMED":
            log.record("vuln", url=args["url"], params=log.extract_params(args["url"]))
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    return result


# ---- 注册表 ----
def _obj(props, required=None):
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


REGISTRY = [
    {
        "name": "save_project",
        "description": "把当前项目关键进展写入中记忆（重启保留，整体覆盖）。确定新目标/重要发现/阶段收尾时调用。",
        "parameters": _obj({"note": {"type": "string", "description": "目标 / 已发现 / 下一步 的简洁要点"}}, ["note"]),
        "handler": _h_save_project,
    },
    {
        "name": "save_case",
        "description": "把刚打通的靶场沉淀成一个 eval case，写进 dev 训练集（供 improve_skill 学习）。任何漏洞验证通过后调用（XSS 用 verify_xss CONFIRMED；SQLi/越权/竞态/上传等用 /api/Challenges solved=true 或直接验证成功）。",
        "parameters": _obj({
            "vuln": {"type": "string", "description": "漏洞大类，如 xss / sqli / idor / race-conditions / logic-flaws / file-upload / info-disclosure / api-rest"},
            "variant": {"type": "string", "description": "漏洞子类型：xss→reflection_xss/dom_xss/stored_xss、sqli→union/blind、idor→basket/order、race→likes、upload→type/size（按 vuln 大类取具体子类）"},
            "context": {"type": "string", "description": "场景：漏洞落在哪个上下文、有什么过滤/编码/校验"},
            "reference_payload": {"type": "string", "description": "成功触发漏洞的 payload/请求（作为参考解）"},
            "principle": {"type": "string", "description": "绕过手法/原理关键词，如「JS 字符串 breakout」「UNION 列数对齐拖库」「竞态窗口重复提交」"},
            "verify_url": {"type": "string", "description": "可选：含 {payload} 占位的可复跑 URL 模板，用于日后真验"},
            "evidence": {"type": "object", "description": "可选：客观证据定义，判分时脱离 LLM 评委核对真值。格式 {\"verify\":\"echo|delay|alert\",\"url\":\"含 {payload} 的 URL 模板\",\"match\":\"回显关键词或延迟秒数\"}。echo=回显匹配（RCE 的 whoami/LFI 的 /etc/passwd/SQLi 拖库字段值）、delay=延迟秒数（盲注 sleep）、alert=XSS 弹窗"},
            "source": {"type": "string", "description": "来源，如 xss-labs / portswigger / dvwa / juice-shop / auto"},
        }, ["vuln", "context", "reference_payload"]),
        "handler": _h_save_case,
    },
    {
        "name": "load_skill",
        "description": "按需读某类漏洞的知识。省略 variant 读该大类全部；指定 variant（如 reflection_xss）只读那一类，省上下文。打靶时根据 overview 判断类型后，只 load 对应的 variant，别一次读全部。",
        "parameters": _obj({
            "vuln": {"type": "string", "description": "漏洞大类，如 xss"},
            "variant": {"type": "string", "description": "可选，子类型如 reflection_xss / dom_xss / stored_xss；省略读全部"},
        }, ["vuln"]),
        "handler": _h_load_skill,
    },
    {
        "name": "run_tool",
        "description": "调用 vendor/ 里的白名单 CLI 工具。按漏洞类型选工具：SQLi→sqlmap、命令注入→commix、文件上传→fuxploider、XSS扫描→dalfox、盲XSS→blindx、WAF绕过→waf-bypass。命令行参数直接传（tool+args 两个参数），调用前先看工具是否 ready。",
        "parameters": _obj({
            "tool": {"type": "string", "description": "工具名，如 sqlmap / commix / fuxploider / blindx / 4-zero-3"},
            "args": {"type": "string", "description": "传给工具的命令行参数，如 '-u http://target?id=1 --batch'"},
        }, ["tool"]),
        "handler": _h_run_tool,
    },
    {
        "name": "run_shell",
        "description": "执行 shell 命令（curl/管道/写文件/Python 脚本）。补执行通路缺 shell 的关键：文件上传的 multipart POST、二次渲染的本地 GD diff、任意命令回显验证都靠它。cwd 固定 tmp 目录，timeout 120s。只用于打靶范围内合法操作。",
        "parameters": _obj({
            "command": {"type": "string", "description": "shell 命令，如 'curl -s -F upload_file=@shell.jpg http://target/upload.php' 或 'python gen_img.py'"},
        }, ["command"]),
        "handler": _h_run_shell,
    },
    {
        "name": "race",
        "description": "并发发 N 个请求（Python 多线程，非顺序），用于条件竞争抢窗口 / 爆破。返回状态码分布。",
        "parameters": _obj({
            "url": {"type": "string", "description": "目标 URL"},
            "count": {"type": "integer", "description": "并发请求数，默认 20"},
            "method": {"type": "string", "description": "HTTP 方法 GET/POST，默认 GET"},
        }, ["url"]),
        "handler": _h_race,
    },
    {
        "name": "search_cve",
        "description": "查 CVE 库：按组件名/关键词搜已知漏洞（NVD）。打 WordPress/已知组件时做版本→CVE 匹配。",
        "parameters": _obj({
            "keyword": {"type": "string", "description": "组件名或关键词，如 'WordPress plugin' / 'Apache Log4j'"},
            "component": {"type": "string", "description": "组件名（同 keyword，二者给一个即可）"},
        }),
        "handler": _h_search_cve,
    },
    {
        "name": "improve_skill",
        "description": "改进某漏洞 skill，经 eval gate 判分（涨保留/跌回滚）。提交后台任务，立即返回，不阻塞对话。",
        "parameters": _obj({
            "vuln": {"type": "string", "description": "漏洞大类，如 xss"},
            "variant": {"type": "string", "description": "类型，如 reflection_xss / dom_xss / stored_xss"},
        }, ["vuln", "variant"]),
        "handler": _h_improve_skill,
    },
    {
        "name": "list_tabs",
        "description": "列出 Chrome 页面并标出 active=true 的前台可见标签；若用户指当前 Chrome 页面，先用此工具定位唯一前台标签。",
        "parameters": _obj({}),
        "handler": _h_list_tabs,
    },
    {
        "name": "close_tab",
        "description": "关闭指定 Chrome 标签（传 list_tabs 给出的 index 或 id）。用于清掉残留的旧靶场页面，避免误导。HackMate 专用测试标签拒绝关闭。",
        "parameters": _obj({
            "index": {"type": "integer", "description": "list_tabs 返回的标签序号"},
            "id": {"type": "string", "description": "标签 id（与 index 二选一）"},
        }),
        "handler": _h_close_tab,
    },
    {
        "name": "open_new_tab",
        "description": "打开或复用 HackMate 专用测试标签。首次创建一个标签，之后始终在同一个标签导航；不要为测试再创建新标签。URL 可省略以保留当前测试页。",
        "parameters": _obj({"url": {"type": "string", "description": "要在专用测试标签打开的 URL；省略时保留当前页面"}}),
        "handler": _h_open_new_tab,
    },
    {
        "name": "read_page_text",
        "description": "读取页面可见文本。读取当前 Chrome 页面时传 list_tabs 给出的 index；省略 index 才读取 HackMate 专用测试标签。",
        "parameters": _obj({"index": {"type": "integer", "description": "list_tabs 返回的标签序号；省略时读取 HackMate 专用测试标签"}}),
        "handler": _h_read_page_text,
    },
    {
        "name": "navigate",
        "description": "在 HackMate 专用测试标签导航到指定 URL；测试期间始终复用同一个标签",
        "parameters": _obj({
            "url": {"type": "string", "description": "目标 URL"},
        }, ["url"]),
        "handler": _h_navigate,
    },
    {
        "name": "fill_form",
        "description": "在第 index 个页面填表单字段（CSS selector + 值，React/Vue 兼容）",
        "parameters": _obj({
            "selector": {"type": "string", "description": "CSS selector，如 #username"},
            "value": {"type": "string", "description": "要填的值"},
        }, ["selector", "value"]),
        "handler": _h_fill_form,
    },
    {
        "name": "write_file",
        "description": "把文件写到 HackMate tmp 目录（造 polyglot 图片马等二进制文件用）。content_base64 传 base64 编码的文件内容，支持二进制。返回文件绝对路径（Windows 路径），配合 upload_file 上传用。",
        "parameters": _obj({
            "path": {"type": "string", "description": "文件名，如 shell.jpg，只能写进 tmp 目录（不能含 ../ 目录穿越）"},
            "content_base64": {"type": "string", "description": "base64 编码的文件内容（二进制文件先 base64）"},
        }, ["path", "content_base64"]),
        "handler": _h_write_file,
    },
    {
        "name": "upload_file",
        "description": "把本地文件通过 CDP DOM.setFileInputFiles 上传到页面的 file input（绕过浏览器 JS 安全限制）。文件上传类漏洞专用：先 write_file 造 polyglot 文件，再 upload_file 上传，最后 click 提交表单。file_path 用 write_file 返回的绝对路径。",
        "parameters": _obj({
            "selector": {"type": "string", "description": "file input 的 CSS selector，如 input[name=upload_file] 或 input[type=file]"},
            "file_path": {"type": "string", "description": "本地文件绝对路径（write_file 返回的 Windows 路径）"},
        }, ["selector", "file_path"]),
        "handler": _h_upload_file,
    },
    {
        "name": "click",
        "description": "点击 HackMate 专用测试标签上的元素（CSS selector）",
        "parameters": _obj({
            "selector": {"type": "string", "description": "CSS selector"},
        }, ["selector"]),
        "handler": _h_click,
    },
    {
        "name": "find_xss_entries",
        "description": "扫描 HackMate 专用测试标签的 XSS 注入点候选（输入框、表单、URL 参数、带参数链接）",
        "parameters": _obj({}),
        "handler": _h_find_xss_entries,
    },
    {
        "name": "enumerate_site",
        "description": "从入口 URL 枚举攻击面：URL 参数、表单（action/method/字段）、输入框、同源链接、JS 文件、JS 里的 API 端点。开放式侦察第一步——真实资产没给定参数，先用这个扫出可注入的攻击面，再逐个打。返回 JSON。",
        "parameters": _obj({
            "url": {"type": "string", "description": "入口 URL，如 http://localhost:8083/ 或 http://target.com/"},
        }, ["url"]),
        "handler": _h_enumerate_site,
    },
    {
        "name": "verify_xss",
        "description": "在 HackMate 专用测试标签黑盒验证 XSS：导航到带 payload 的完整 URL，检测 alert 弹窗是否触发（触发=JS 执行=XSS 成立）",
        "parameters": _obj({
            "url": {"type": "string", "description": "带 XSS payload 的完整 URL"},
        }, ["url"]),
        "handler": _h_verify_xss,
    },
]

_BY_NAME = {t["name"]: t for t in REGISTRY}


def schemas():
    """生成给 LLM 的 function-calling 工具列表。"""
    return [{"type": "function",
             "function": {"name": t["name"], "description": t["description"],
                          "parameters": t["parameters"]}}
            for t in REGISTRY]


def dispatch(name, args, ctx):
    """执行一个工具调用，返回结果字符串。"""
    t = _BY_NAME.get(name)
    if t is None:
        return f"未知工具: {name}"
    try:
        return t["handler"](args, ctx)
    except Exception as e:
        return f"工具执行错误: {e}"


def _mcp_schema(tool):
    """把 MCP 工具的 inputSchema（JSON Schema）转成 HackMate parameters 格式。"""
    schema = tool.get("inputSchema") or {}
    if schema.get("type") == "object" and "properties" in schema:
        return schema
    return {"type": "object", "properties": {}}


def discover_mcp(cfg):
    """连 cfg['mcp_servers'] 里配的 MCP 服务器，把其工具动态注册进 REGISTRY。

    工具名统一加 mcp_<server>_<tool> 前缀（连字符/点转下划线，兼容 LLM API）。
    连不上的服务器跳过，不影响其他 server 和内置工具。
    返回 (成功连接的 server 数, 注册的工具数)。
    """
    servers = cfg.get("mcp_servers") or []
    if not servers:
        return 0, 0
    from . import mcp_client as mcp
    n_conn = n_tool = 0
    for srv in servers:
        name, command = srv.get("name", ""), srv.get("command", "")
        if not name or not command:
            continue
        try:
            c = mcp.MCPClient(name, command, srv.get("args", []),
                              srv.get("env", {}), srv.get("timeout", 120))
            tools = c.connect()
            n_conn += 1
            for t in tools:
                tn = t.get("name", "")
                full = f"mcp_{name}_{tn}".replace("-", "_").replace(".", "_")
                REGISTRY.append({
                    "name": full,
                    "description": f"[MCP:{name}] {t.get('description', '')}",
                    "parameters": _mcp_schema(t),
                    "handler": (lambda a, ctx, _c=c, _tn=tn: _c.call(_tn, a)),
                })
                n_tool += 1
        except Exception as e:
            print(f"[MCP] 连 '{name}' 失败：{e}")
    global _BY_NAME
    _BY_NAME = {t["name"]: t for t in REGISTRY}
    return n_conn, n_tool
