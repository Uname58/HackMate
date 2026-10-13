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
    return result


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
    tabs = _cdp(ctx).list_tabs()
    return json.dumps([{"index": i, "title": t["title"], "url": t["url"]}
                       for i, t in enumerate(tabs)], ensure_ascii=False)


def _h_open_new_tab(args, ctx):
    tab = _cdp(ctx).open_new_tab(args.get("url", "about:blank"))
    return json.dumps({"opened": tab.get("title", ""), "url": tab.get("url", "")},
                      ensure_ascii=False)


def _h_read_page_text(args, ctx):
    c = _cdp(ctx)
    tabs = c.list_tabs()
    idx = int(args.get("index", 0))
    if not (0 <= idx < len(tabs)):
        return f"序号 {idx} 超出范围（0-{len(tabs)-1}）"
    text = c.read_page_text(tabs[idx])
    return text[:2000] if len(text) > 2000 else text


def _h_navigate(args, ctx):
    return _cdp(ctx).navigate(args.get("url", "about:blank"), int(args.get("index", 0)))


def _h_fill_form(args, ctx):
    return _cdp(ctx).fill_form(args["selector"], args["value"], int(args.get("index", 0)))


def _h_click(args, ctx):
    return _cdp(ctx).click(args["selector"], int(args.get("index", 0)))


def _h_find_xss_entries(args, ctx):
    return _cdp(ctx).find_xss_entries(int(args.get("index", 0)))


def _h_verify_xss(args, ctx):
    result = _cdp(ctx).verify_xss(args["url"], int(args.get("index", 0)))
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
        "description": "列出 Chrome 当前打开的所有页面（标题和 URL）",
        "parameters": _obj({}),
        "handler": _h_list_tabs,
    },
    {
        "name": "open_new_tab",
        "description": "在 Chrome 里开一个新标签页并导航到指定 URL（空白页用 about:blank）",
        "parameters": _obj({"url": {"type": "string", "description": "要打开的 URL，默认 about:blank"}}),
        "handler": _h_open_new_tab,
    },
    {
        "name": "read_page_text",
        "description": "读第 index 个页面的可见文本内容",
        "parameters": _obj({"index": {"type": "integer", "description": "页面序号，从 0 开始"}}, ["index"]),
        "handler": _h_read_page_text,
    },
    {
        "name": "navigate",
        "description": "导航第 index 个页面到指定 URL",
        "parameters": _obj({
            "url": {"type": "string", "description": "目标 URL"},
            "index": {"type": "integer", "description": "页面序号，默认 0"},
        }, ["url"]),
        "handler": _h_navigate,
    },
    {
        "name": "fill_form",
        "description": "在第 index 个页面填表单字段（CSS selector + 值，React/Vue 兼容）",
        "parameters": _obj({
            "selector": {"type": "string", "description": "CSS selector，如 #username"},
            "value": {"type": "string", "description": "要填的值"},
            "index": {"type": "integer", "description": "页面序号，默认 0"},
        }, ["selector", "value"]),
        "handler": _h_fill_form,
    },
    {
        "name": "click",
        "description": "点击第 index 个页面上的元素（CSS selector）",
        "parameters": _obj({
            "selector": {"type": "string", "description": "CSS selector"},
            "index": {"type": "integer", "description": "页面序号，默认 0"},
        }, ["selector"]),
        "handler": _h_click,
    },
    {
        "name": "find_xss_entries",
        "description": "扫描第 index 个页面的 XSS 注入点候选（输入框、表单、URL 参数、带参数链接）",
        "parameters": _obj({"index": {"type": "integer", "description": "页面序号，默认 0"}}),
        "handler": _h_find_xss_entries,
    },
    {
        "name": "verify_xss",
        "description": "黑盒验证 XSS：导航到带 payload 的完整 URL，检测 alert 弹窗是否触发（触发=JS 执行=XSS 成立）",
        "parameters": _obj({
            "url": {"type": "string", "description": "带 XSS payload 的完整 URL"},
            "index": {"type": "integer", "description": "页面序号，默认 0"},
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
