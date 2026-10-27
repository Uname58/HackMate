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
    content = skill.load_skill(args.get("vuln", ""))
    return content if content else "没有该漏洞的知识"


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


def _h_click(args, ctx):
    return _cdp(ctx).click(args["selector"], test_tab=True)


def _h_find_xss_entries(args, ctx):
    return _cdp(ctx).find_xss_entries(test_tab=True)


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
        "description": "把刚打通的靶场沉淀成一个 eval case，写进 dev 训练集（供 improve_skill 学习）。仅在 verify_xss 返回 CONFIRMED 后调用。",
        "parameters": _obj({
            "vuln": {"type": "string", "description": "漏洞大类，如 xss"},
            "variant": {"type": "string", "description": "漏洞类型，如 reflection_xss / dom_xss / stored_xss（默认 reflection_xss）"},
            "context": {"type": "string", "description": "场景：反射点落在哪个上下文、有什么过滤/编码"},
            "reference_payload": {"type": "string", "description": "成功触发执行的 payload（作为参考解）"},
            "principle": {"type": "string", "description": "绕过手法/原理关键词，如「JS 字符串 breakout」"},
            "verify_url": {"type": "string", "description": "可选：含 {payload} 占位的可复跑 URL 模板，用于日后真验"},
            "source": {"type": "string", "description": "来源，如 xss-labs / portswigger / auto"},
        }, ["vuln", "context", "reference_payload"]),
        "handler": _h_save_case,
    },
    {
        "name": "load_skill",
        "description": "读某类漏洞的完整知识（测试方法/绕过手法/坑），注入上下文",
        "parameters": _obj({"vuln": {"type": "string", "description": "漏洞大类，如 xss"}}, ["vuln"]),
        "handler": _h_load_skill,
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
