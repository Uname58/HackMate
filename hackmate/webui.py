"""本地 Web 工作台：复用 HackMate 的对话客户端和工具注册表。"""

import argparse
from html.parser import HTMLParser
import json
import socket
import re
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser
import webbrowser

from .config import load_config
from .jobs import JobManager
from .llm import LLMClient, LLMCancelled, LLMError
from . import log, memory
from .repl import HELP, build_system_prompt
from .tools import ToolContext, dispatch, schemas

WEB_DIR = Path(__file__).resolve().parent / "web"
MAX_CHAT_CHARS = 12000
MAX_ACTIONS = 500
_LOCAL_UI_LOCK = threading.Lock()
_LOCAL_UI_SERVER = None
_LOCAL_UI_THREAD = None
_LOCAL_UI_URL = ""

_TOOL_LABELS = {
    "help": ("帮助", "?"),
    "web": ("工作台", "↗"),
    "command": ("本地命令", "⌘"),
    "save_project": ("存进度", "▣"),
    "save_case": ("记录 case", "✎"),
    "load_skill": ("读 skill", "▤"),
    "improve_skill": ("提交 skill 优化", "⚙"),
    "list_tabs": ("列标签", "▧"),
    "open_new_tab": ("打开 / 复用测试页", "↗"),
    "navigate": ("导航", "↗"),
    "read_page_text": ("读页面文本", "≡"),
    "fill_form": ("填表单", "⌑"),
    "click": ("点击页面元素", "⌖"),
    "find_xss_entries": ("侦察注入点", "⌕"),
    "verify_xss": ("验证 XSS", "✓"),
    "recon": ("全站 Recon", "⌕"),
    "stop": ("停止当前任务", "■"),
}

_WEB_COMMANDS = {
    "/help", "/web", "/clear", "/stop", "/cdp", "/guide", "/skill",
    "/memory", "/log", "/jobs", "/job", "/cancel", "/exit", "/quit",
}
_WEB_HELP = HELP.rstrip() + (
    "\n\nWeb 工作台命令：\n"
    "  /help         在工作区显示帮助\n"
    "  /web          当前已在 Web 工作台中\n"
    "  其他 CLI 命令暂不支持，不会发送给 HackMate\n"
)

_RECON_MAX_PAGES = 300
_RECON_MAX_DEPTH = 8
_RECON_MAX_HTML_BYTES = 1_000_000
_RECON_SKIP_EXTENSIONS = {
    ".7z", ".avi", ".css", ".csv", ".doc", ".docx", ".eot", ".gif",
    ".gz", ".ico", ".jpeg", ".jpg", ".js", ".json", ".map", ".mp3",
    ".mp4", ".pdf", ".png", ".ppt", ".pptx", ".rar", ".svg", ".tar",
    ".ttf", ".webm", ".webp", ".woff", ".woff2", ".xls", ".xlsx", ".zip",
}
_RECON_SKIP_PATH = re.compile(r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe)(?:/|$)", re.I)


class _AnchorParser(HTMLParser):
    """Collect same-page navigation candidates without executing page scripts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []
        self.base_href = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "base" and not self.base_href:
            self.base_href = attrs.get("href", "")
        elif tag.lower() == "a" and attrs.get("href"):
            self.hrefs.append(attrs["href"])


def _natural_sort_key(value):
    return tuple((1, int(part)) if part.isdigit() else (0, part.casefold())
                 for part in re.split(r"(\d+)", str(value)))


def _safe_url(url):
    """只把 HTTP(S) URL 纳入站点树，并从节点显示中剥离查询值。"""
    value = str(url or "").strip()
    if value.startswith("view-source:"):
        value = value[len("view-source:"):]
    try:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        host = parts.netloc
        path = parts.path or "/"
        label = path
        return {"origin": f"{parts.scheme}://{host}", "host": host,
                "path": path, "label": label,
                "url": f"{parts.scheme}://{host}{parts.path}"}
    except (ValueError, UnicodeError):
        return None


class WebSession:
    """单个本机 UI 会话；LLM 上下文和展示状态都只存在当前进程内。"""

    def __init__(self):
        self.cfg = load_config()
        self.client = LLMClient(self.cfg["base_url"], self.cfg["api_key"],
                                self.cfg["model"], build_system_prompt(self.cfg))
        self.jobs = JobManager()
        self.tool_schemas = schemas()
        self._lock = threading.RLock()
        self._busy = False
        self._cancel_event = None
        self._stop_action_id = None
        self._chat = []
        self._actions = deque(maxlen=MAX_ACTIONS)
        self._action_id = 0
        self._seen_urls = {}
        self._recon = {"running": False, "origin": "", "visited": 0,
                       "found": 0, "error": ""}
        self._recon_action_id = None
        self._job_states = {}
        self._cdp = None
        self._cdp_checked_at = 0.0
        self._cdp_check_interval = 4.0
        self._cdp_refresh_lock = threading.Lock()
        self._cdp_error = ""
        self._tool_ctx = ToolContext(self.cfg, self.client, self.jobs, self._get_cdp)
        # 页面和对话先立即可用；CDP 探测在后台运行，失联时不阻塞 Web 请求。
        self._cdp_error = "CDP 未连接"
        self._refresh_cdp()

    def _get_cdp(self):
        if self._cdp is not None:
            try:
                self._cdp._get_json("/json/version")
                return self._cdp
            except Exception:
                self._cdp = None
        from .cdp import ensure_cdp
        self._cdp = ensure_cdp(self.cfg["cdp_host"], int(self.cfg["cdp_port"]),
                               auto_launch=True)
        self._cdp_checked_at = time.monotonic()
        if self._cdp is None:
            raise RuntimeError("CDP 未连接；请启动调试 Chrome 后重试")
        self._cdp_error = ""
        self._sync_tabs()
        return self._cdp

    def _sync_tabs(self):
        cdp = self._cdp
        if cdp is None:
            return
        try:
            found = []
            for tab in cdp.list_tabs():
                item = _safe_url(tab.get("url"))
                if item:
                    found.append(item)
            with self._lock:
                for item in found:
                    self._seen_urls[item["origin"] + item["path"]] = item
                self._cdp_error = ""
        except Exception as exc:
            with self._lock:
                self._cdp_error = str(exc)

    def start_recon(self, origin=None):
        with self._lock:
            targets = self._site_tree()
        allowed_origins = {target["origin"] for target in targets}
        if not allowed_origins:
            return False, "还没有发现目标网站；先在 Chrome 中打开目标页面。"
        selected = str(origin or targets[0]["origin"]).rstrip("/")
        if selected not in allowed_origins:
            return False, "Recon 只能扫描左侧结构树中已发现的网站。"
        with self._lock:
            if self._recon["running"]:
                return False, "Recon 正在运行。"
            self._recon = {"running": True, "origin": selected,
                           "visited": 0, "found": 0, "error": ""}
            action = self._push_action("recon", {"url": selected},
                                       status="running", result="准备扫描同源页面…")
            self._recon_action_id = action["id"]
        worker = threading.Thread(target=self._run_recon, args=(selected,),
                                  daemon=True, name="hackmate-web-recon")
        worker.start()
        return True, ""

    def _run_recon(self, origin):
        with self._lock:
            seeds = {origin + "/"}
            seeds.update(origin + item["path"] for item in self._seen_urls.values()
                         if item["origin"] == origin)
        queue = deque((url, 0) for url in sorted(seeds, key=_natural_sort_key))
        scheduled = set(seeds)
        visited = set()
        found = set()
        error = ""
        robots = RobotFileParser()
        robots.set_url(origin + "/robots.txt")
        try:
            request = Request(origin + "/robots.txt", headers={"User-Agent": "HackMate-Recon/1.0"})
            with urlopen(request, timeout=3) as response:
                robots.parse(response.read(256_000).decode("utf-8", "replace").splitlines())
        except Exception:
            # 缺少 robots.txt 时按常规站点链接继续；每次请求仍限制在当前 origin。
            robots.parse([])

        try:
            while queue and len(visited) < _RECON_MAX_PAGES:
                page_url, depth = queue.popleft()
                if page_url in visited:
                    continue
                visited.add(page_url)
                item = _safe_url(page_url)
                if item:
                    with self._lock:
                        self._seen_urls[item["origin"] + item["path"]] = item
                if not robots.can_fetch("HackMate-Recon", page_url):
                    continue
                try:
                    request = Request(page_url, headers={
                        "User-Agent": "HackMate-Recon/1.0",
                        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                    })
                    with urlopen(request, timeout=4) as response:
                        final_url = response.geturl()
                        final_parts = urlsplit(final_url)
                        if f"{final_parts.scheme}://{final_parts.netloc}".lower() != origin.lower():
                            continue
                        content_type = response.headers.get_content_type().lower()
                        if content_type not in ("text/html", "application/xhtml+xml"):
                            continue
                        charset = response.headers.get_content_charset() or "utf-8"
                        document = response.read(_RECON_MAX_HTML_BYTES).decode(charset, "replace")
                    parser = _AnchorParser()
                    parser.feed(document)
                except Exception:
                    continue

                base_url = urljoin(final_url, parser.base_href) if parser.base_href else final_url
                if depth < _RECON_MAX_DEPTH:
                    for href in parser.hrefs:
                        candidate = urljoin(base_url, href)
                        parts = urlsplit(candidate)
                        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
                            continue
                        candidate_origin = f"{parts.scheme}://{parts.netloc}"
                        if candidate_origin.lower() != origin.lower():
                            continue
                        path = parts.path or "/"
                        if (Path(path).suffix.lower() in _RECON_SKIP_EXTENSIONS or
                                _RECON_SKIP_PATH.search(path)):
                            continue
                        candidate = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
                        found.add(candidate)
                        discovered = _safe_url(candidate)
                        if discovered:
                            with self._lock:
                                self._seen_urls[discovered["origin"] + discovered["path"]] = discovered
                        if candidate not in scheduled and candidate not in visited:
                            scheduled.add(candidate)
                            queue.append((candidate, depth + 1))

                with self._lock:
                    self._recon.update({"visited": len(visited), "found": len(found)})
                    if self._recon_action_id is not None:
                        self._finish_action(
                            self._recon_action_id,
                            f"已检查 {len(visited)} 页，发现 {len(found)} 个站内路径",
                            "running",
                        )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._recon.update({"running": False, "visited": len(visited),
                                    "found": len(found), "error": error})
                if self._recon_action_id is not None:
                    if error:
                        self._finish_action(self._recon_action_id, f"扫描出错：{error}", "failed")
                    else:
                        limit_note = "（达到页面上限）" if queue else ""
                        self._finish_action(
                            self._recon_action_id,
                            f"完成：检查 {len(visited)} 页，发现 {len(found)} 个站内路径{limit_note}",
                        )
                self._recon_action_id = None

    def _refresh_cdp(self):
        now = time.monotonic()
        if now - self._cdp_checked_at < self._cdp_check_interval:
            return
        if not self._cdp_refresh_lock.acquire(blocking=False):
            return
        self._cdp_checked_at = now
        worker = threading.Thread(target=self._probe_cdp, daemon=True,
                                  name="hackmate-web-cdp-status")
        worker.start()

    def _probe_cdp(self):
        try:
            with self._lock:
                cdp = self._cdp
            if cdp is None:
                from .cdp import ensure_cdp
                cdp = ensure_cdp(self.cfg["cdp_host"], int(self.cfg["cdp_port"]),
                                 auto_launch=False)
                if cdp is None:
                    with self._lock:
                        self._cdp_error = "CDP 未连接"
                    return
            else:
                cdp._get_json("/json/version")
            with self._lock:
                if self._cdp is None:
                    self._cdp = cdp
            self._sync_tabs()
        except Exception as exc:
            with self._lock:
                if self._cdp is cdp:
                    self._cdp = None
                self._cdp_error = str(exc)
        finally:
            self._cdp_checked_at = time.monotonic()
            self._cdp_refresh_lock.release()

    def _push_action(self, name, args=None, status="running", result=""):
        args = args or {}
        label, icon = _TOOL_LABELS.get(name, (name, "·"))
        detail = (args.get("url") or args.get("selector") or args.get("vuln") or
                  args.get("variant") or args.get("note") or "")
        with self._lock:
            self._action_id += 1
            action = {
                "id": self._action_id, "name": name, "label": label, "icon": icon,
                "detail": str(detail)[:1200], "result": str(result)[:1200],
                "status": status, "time": time.strftime("%H:%M:%S"),
            }
            self._actions.append(action)
            return action

    def _finish_action(self, action_id, result, status="done"):
        with self._lock:
            for action in self._actions:
                if action["id"] == action_id:
                    action["result"] = str(result)[:1200]
                    action["status"] = status
                    break

    def submit(self, text):
        text = str(text or "").strip()
        if not text:
            return False, "请输入消息"
        if len(text) > MAX_CHAT_CHARS:
            return False, f"单条消息不能超过 {MAX_CHAT_CHARS} 个字符"
        with self._lock:
            if self._busy:
                return False, "HackMate 正在处理上一条消息"
            if text == "/help":
                self._push_action("help", status="done", result=_WEB_HELP)
                return True, ""
            if text == "/web":
                self._push_action("web", status="done", result="当前已经在 Web 工作台中。")
                return True, ""
            command = text.split(maxsplit=1)[0]
            if command in _WEB_COMMANDS:
                self._push_action(
                    "command", status="done",
                    result=f"{command} 是 CLI 命令，Web 工作台暂不支持；该命令没有发送给 HackMate。",
                )
                return True, ""
            self._busy = True
            self._cancel_event = threading.Event()
            self.client.set_cancel_event(self._cancel_event)
            self._chat.append({"role": "user", "content": text, "time": time.strftime("%H:%M:%S")})
        if not self.cfg["api_key"]:
            self._append_assistant("尚未配置 API Key。请在项目 `.env` 中设置 HACKMATE_API_KEY 后重启工作台。")
            with self._lock:
                self._busy = False
                self._cancel_event = None
                self.client.set_cancel_event(None)
            return True, ""
        worker = threading.Thread(target=self._respond, args=(text, self._cancel_event), daemon=True,
                                  name="hackmate-web-chat")
        worker.start()
        return True, ""

    def stop_current(self):
        with self._lock:
            if not self._busy or self._cancel_event is None:
                return False, "当前没有运行中的任务"
            if self._cancel_event.is_set():
                return True, "停止请求已提交"
            self._cancel_event.set()
            action = self._push_action("stop", status="running", result="正在停止当前任务…")
            self._stop_action_id = action["id"]
        self.client.abort()
        return True, "停止请求已提交"

    def _append_assistant(self, text):
        with self._lock:
            self._chat.append({"role": "assistant", "content": str(text or ""),
                               "time": time.strftime("%H:%M:%S")})

    def _respond(self, text, cancel_event):
        try:
            response = self.client.chat(text, tools=self.tool_schemas)
            while not cancel_event.is_set() and response.get("type") == "tool_calls":
                results = []
                for call in response["tool_calls"]:
                    if cancel_event.is_set():
                        break
                    fn = call["function"]["name"]
                    try:
                        args = json.loads(call["function"].get("arguments") or "{}")
                    except (json.JSONDecodeError, TypeError):
                        args = {}
                    action = self._push_action(fn, args)
                    result = dispatch(fn, args, self._tool_ctx)
                    failed = str(result).startswith("工具执行错误:")
                    self._finish_action(action["id"], result,
                                        "failed" if failed else "done")
                    if fn == "improve_skill":
                        job_match = re.search(r"#(\d+)", str(result))
                        if job_match:
                            action["job_id"] = int(job_match.group(1))
                    if fn in ("navigate", "open_new_tab") and not failed:
                        item = _safe_url(args.get("url"))
                        if item:
                            with self._lock:
                                self._seen_urls[item["origin"] + item["path"]] = item
                    if fn == "verify_xss":
                        try:
                            status = json.loads(result).get("status", "")
                            if status:
                                self._finish_action(action["id"], result,
                                                    "confirmed" if status == "CONFIRMED" else "done")
                        except (json.JSONDecodeError, TypeError, AttributeError):
                            pass
                    log.record_step(fn, args, result)
                    results.append((call["id"], fn, result))
                    self._sync_tabs()
                    if cancel_event.is_set():
                        break
                if cancel_event.is_set():
                    break
                response = self.client.submit_tool_results(results, tools=self.tool_schemas)
                self.client.compact()
            if not cancel_event.is_set() and response.get("type") == "text" and response.get("content"):
                self._append_assistant(response["content"])
        except LLMCancelled:
            pass
        except LLMError as exc:
            if not cancel_event.is_set():
                self._append_assistant(f"请求失败：{exc}")
        except Exception as exc:
            if not cancel_event.is_set():
                self._append_assistant(f"处理时出错：{type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                if cancel_event.is_set():
                    memory.mark_project_interrupted()
                    log.record_task_interrupted()
                    self.client.system_prompt = build_system_prompt(self.cfg)
                    self.client.clear()
                    self._chat.append({
                        "role": "assistant",
                        "content": "当前任务已中止并标记为未完成。下次开始时会重新核对当前目标。",
                        "time": time.strftime("%H:%M:%S"),
                    })
                    if self._stop_action_id is not None:
                        self._finish_action(self._stop_action_id, "当前任务已停止", "done")
                self._stop_action_id = None
                self._cancel_event = None
                self.client.set_cancel_event(None)
                self._busy = False

    def _sync_jobs(self):
        for job in self.jobs.list_jobs():
            state = (job.status, job.progress, job.result, job.error)
            old = self._job_states.get(job.id)
            if old == state:
                continue
            self._job_states[job.id] = state
            status = "running" if not job.finished else ("failed" if job.error else "done")
            action = next((a for a in self._actions if a.get("job_id") == job.id), None)
            if action is None:
                action = self._push_action("improve_skill", {"variant": job.title}, status)
                action["job_id"] = job.id
            result = job.progress or job.result or job.error or job.status
            self._finish_action(action["id"], result, status)

    def _site_tree(self):
        groups = {}
        for item in self._seen_urls.values():
            root = groups.setdefault(item["origin"], {"origin": item["origin"], "host": item["host"], "pages": {}})
            root["pages"][item["path"]] = dict(item)
        return [{"origin": group["origin"], "host": group["host"],
                 "pages": sorted(group["pages"].values(), key=lambda p: _natural_sort_key(p["path"]))}
                for group in sorted(groups.values(), key=lambda x: x["host"])]

    def state(self):
        self._refresh_cdp()
        with self._lock:
            self._sync_jobs()
            return {
                "chat": [dict(item) for item in self._chat],
                "actions": [dict(item) for item in self._actions],
                "targets": self._site_tree(),
                "recon": dict(self._recon),
                "busy": self._busy,
                "cancel_requested": bool(self._cancel_event and self._cancel_event.is_set()),
                "configured": bool(self.cfg["api_key"]),
                "cdp_connected": self._cdp is not None and not self._cdp_error,
                "cdp_error": self._cdp_error,
                "model": self.cfg["model"],
                "tools": [
                    {"id": "traffic", "name": "抓包 / 修改包", "group": "流量分析",
                     "description": "HTTP 历史、请求编辑与重放", "status": "未接入"},
                    {"id": "xsstrike", "name": "XSStrike", "group": "安全测试",
                     "description": "XSS 检测与 payload 分析", "status": "未配置"},
                    {"id": "hackmate", "name": "HackMate 浏览器工具", "group": "安全测试",
                     "description": "CDP 页面侦察与验证", "status": "可用"},
                ],
            }


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_handler(session, port):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HackMateWeb/1.0"

        def _send(self, status, body, content_type="application/json; charset=utf-8"):
            if isinstance(body, str):
                data = body.encode("utf-8")
            else:
                data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                # 页面重载或关闭时，允许被中断的轮询请求正常结束。
                pass

        def _local_request(self):
            allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
            if self.headers.get("Host", "") not in allowed:
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
                return False
            return True

        def do_GET(self):
            if not self._local_request():
                self._send(403, {"error": "仅允许本机访问"})
                return
            if self.path == "/":
                page = WEB_DIR / "index.html"
                if not page.is_file():
                    self._send(404, "工作台页面未安装", "text/plain; charset=utf-8")
                    return
                self._send(200, page.read_text(encoding="utf-8"), "text/html; charset=utf-8")
            elif self.path == "/api/state":
                self._send(200, session.state())
            elif self.path == "/favicon.ico":
                self._send(204, "", "image/x-icon")
            else:
                self._send(404, {"error": "Not found"})

        def do_POST(self):
            if not self._local_request():
                self._send(403, {"error": "仅允许本机访问"})
                return
            if self.path not in ("/api/chat", "/api/stop", "/api/recon"):
                self._send(404, {"error": "Not found"})
                return
            if self.path == "/api/stop":
                accepted, error = session.stop_current()
                self._send(202 if accepted else 409,
                           {"accepted": accepted, **({} if accepted else {"error": error})})
                return
            if self.path == "/api/recon":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length > 4096:
                        self._send(413, {"error": "请求长度无效"})
                        return
                    payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                    accepted, error = session.start_recon(payload.get("origin"))
                    if not accepted:
                        self._send(409, {"error": error})
                        return
                    self._send(202, {"accepted": True})
                except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                    self._send(400, {"error": "请求 JSON 无效"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_CHAT_CHARS * 4:
                    self._send(413, {"error": "消息长度无效"})
                    return
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                accepted, error = session.submit(payload.get("text", ""))
                if not accepted:
                    self._send(409, {"error": error})
                    return
                self._send(202, {"accepted": True})
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                self._send(400, {"error": "请求 JSON 无效"})

        def log_message(self, fmt, *args):
            # 该服务器可能嵌在 REPL 进程里；后台请求日志写到终端会打断 input() 的行编辑。
            # 工作台状态可在 UI 查看，避免请求日志污染 CLI 输入。
            return

    return Handler


def serve(host="127.0.0.1", port=8765):
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("HackMate Web UI 仅绑定本机回环地址")
    session = WebSession()
    bind_host = "127.0.0.1" if host == "localhost" else host
    server = _HTTPServer((bind_host, int(port)), make_handler(session, int(port)))
    actual_port = server.server_address[1]
    print(f"HackMate 工作台已启动: http://127.0.0.1:{actual_port}")
    print("按 Ctrl+C 停止。对话和行动记录仅保存在本次运行内存中。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nHackMate 工作台已停止。")
    finally:
        server.server_close()
    return 0


def _existing_ui(port):
    url = f"http://127.0.0.1:{port}"
    try:
        with urlopen(url, timeout=0.4) as response:
            return url if response.headers.get("Server", "").startswith("HackMateWeb/") else ""
    except Exception:
        return ""


def open_ui(port=8765):
    """在 CLI 进程中启动本机 UI（如未运行）并交给默认浏览器打开。"""
    global _LOCAL_UI_SERVER, _LOCAL_UI_THREAD, _LOCAL_UI_URL
    with _LOCAL_UI_LOCK:
        if _LOCAL_UI_SERVER is not None:
            url = _LOCAL_UI_URL
        else:
            url = _existing_ui(port)
            if not url:
                selected_port = None
                for candidate in range(int(port), int(port) + 20):
                    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        probe.bind(("127.0.0.1", candidate))
                        selected_port = candidate
                        break
                    except OSError:
                        url = _existing_ui(candidate)
                        if url:
                            break
                    finally:
                        probe.close()
                if not url:
                    if selected_port is None:
                        raise OSError(f"端口 {port}-{int(port) + 19} 均不可用")
                    session = WebSession()
                    _LOCAL_UI_SERVER = _HTTPServer(
                        ("127.0.0.1", selected_port), make_handler(session, selected_port))
                    _LOCAL_UI_THREAD = threading.Thread(
                        target=_LOCAL_UI_SERVER.serve_forever,
                        name="hackmate-web-ui", daemon=True)
                    _LOCAL_UI_THREAD.start()
                    url = f"http://127.0.0.1:{selected_port}"
                    _LOCAL_UI_URL = url
    try:
        opened = webbrowser.open(url, new=2)
    except Exception:
        opened = False
    return url, bool(opened)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hackmate web", description="启动本机 HackMate Web 工作台")
    parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"))
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    return serve(args.host, args.port)
