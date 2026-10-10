"""CDP 客户端 —— 读 Chrome 状态 + 页面 DOM。

- HTTP 端点：列 tab、读标题/URL（零依赖）
- WebSocket：读页面 DOM（可见文本 / HTML），需要 websocket-client
"""

import json
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path

from .config import app_root

try:
    import websocket  # websocket-client，用于读 DOM
    _HAS_WS = True
except ImportError:
    websocket = None
    _HAS_WS = False


class CDPError(Exception):
    pass


class CDPClient:
    def __init__(self, host="localhost", port=9222, timeout=5):
        self.host = host
        self.port = port
        self.base = f"http://{host}:{port}"
        self.timeout = timeout

    def _get_json(self, path):
        url = f"{self.base}{path}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            raise CDPError(f"无法连接 CDP ({url}): {e}")

    def list_tabs(self):
        """列出所有正常页面 tab（过滤 browser_ui / 扩展等内部 UI）。"""
        data = self._get_json("/json")
        tabs = []
        for t in data:
            if t.get("type") != "page":
                continue
            tabs.append({
                "id": t.get("id", ""),
                "title": t.get("title", ""),
                "url": t.get("url", ""),
                "ws": t.get("webSocketDebuggerUrl", ""),
            })
        return tabs

    def open_new_tab(self, url="about:blank"):
        """开新标签页（HTTP PUT /json/new）。返回新 tab 信息。"""
        from urllib.parse import quote
        req = urllib.request.Request(
            f"{self.base}/json/new?{quote(url, safe=':/?&=')}",
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            raise CDPError(f"开新标签页失败: {e}")

    def _cdp_cmd(self, ws_url, method, params=None, timeout=10):
        """通过 WebSocket 发任意 CDP 命令，返回 result dict。"""
        if not _HAS_WS:
            raise CDPError("缺少 websocket-client，请 pip install websocket-client")
        ws = websocket.create_connection(ws_url, timeout=timeout)
        try:
            ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
            msg = None
            while True:
                msg = json.loads(ws.recv())
                if msg.get("id") == 1:
                    break
        finally:
            ws.close()
        if msg.get("error"):
            raise CDPError(f"CDP {method} 错误: {msg['error'].get('message', '')}")
        return msg.get("result", {})

    def _cdp_eval(self, ws_url, expression, timeout=10):
        """通过 Runtime.evaluate 执行 JS，返回结果值。"""
        result = self._cdp_cmd(
            ws_url, "Runtime.evaluate",
            {"expression": expression, "returnByValue": True}, timeout,
        )
        r = result.get("result", {})
        if r.get("subtype") == "error":
            raise CDPError(f"Runtime.evaluate 出错: {r.get('description', '')}")
        return r.get("value", "")

    def _get_tab(self, index=0):
        """取第 index 个 page tab。"""
        tabs = self.list_tabs()
        if not (0 <= index < len(tabs)):
            raise CDPError(f"序号 {index} 超出范围（0-{len(tabs)-1}）")
        return tabs[index]

    def navigate(self, url, index=0):
        """导航第 index 个页面到 url（CDP Page.navigate）。"""
        tab = self._get_tab(index)
        self._cdp_cmd(tab["ws"], "Page.navigate", {"url": url})
        return f"已导航到 {url}"

    def fill_form(self, selector, value, index=0):
        """在第 index 个页面填表单字段（React/Vue 兼容）。"""
        tab = self._get_tab(index)
        js = (
            "(function(){"
            f"const el=document.querySelector({json.dumps(selector)});"
            "if(!el)return '未找到元素: '+" + json.dumps(selector) + ";"
            "if(el.tagName==='SELECT'){"
            f"el.value={json.dumps(value)};"
            "el.dispatchEvent(new Event('change',{bubbles:true}));"
            "return '已选: '+" + json.dumps(selector) + ";"
            "}"
            "const proto=el.tagName==='TEXTAREA'?window.HTMLTextAreaElement.prototype:window.HTMLInputElement.prototype;"
            f"Object.getOwnPropertyDescriptor(proto,'value').set.call(el,{json.dumps(value)});"
            "el.dispatchEvent(new Event('input',{bubbles:true}));"
            "el.dispatchEvent(new Event('change',{bubbles:true}));"
            "return '已填: '+" + json.dumps(selector) + ";"
            "})()"
        )
        return self._cdp_eval(tab["ws"], js)

    def click(self, selector, index=0):
        """点击第 index 个页面上的元素。"""
        tab = self._get_tab(index)
        js = (
            "(function(){"
            f"const el=document.querySelector({json.dumps(selector)});"
            "if(!el)return '未找到元素: '+" + json.dumps(selector) + ";"
            "el.click();"
            "return '已点击: '+" + json.dumps(selector) + ";"
            "})()"
        )
        return self._cdp_eval(tab["ws"], js)

    def find_xss_entries(self, index=0):
        """扫描第 index 个页面的 XSS 注入点候选（表单/输入框/URL 参数/带参数链接）。"""
        tab = self._get_tab(index)
        js = (
            "(function(){"
            "const out={url:location.href,"
            "url_params:Array.from(new URLSearchParams(location.search).keys()),"
            "inputs:[],textareas:[],selects:[],forms:[],links_with_params:[]};"
            "document.querySelectorAll('input').forEach(el=>{out.inputs.push("
            "{name:el.name||'',type:el.type||'',id:el.id||'',placeholder:el.placeholder||''})});"
            "document.querySelectorAll('textarea').forEach(el=>{out.textareas.push("
            "{name:el.name||'',id:el.id||'',placeholder:el.placeholder||''})});"
            "document.querySelectorAll('select').forEach(el=>{out.selects.push("
            "{name:el.name||'',id:el.id||''})});"
            "document.querySelectorAll('form').forEach(el=>{out.forms.push("
            "{action:el.action||'',method:el.method||''})});"
            "document.querySelectorAll('a[href*=\"?\"]').forEach(el=>{out.links_with_params.push("
            "{text:(el.innerText||'').trim().slice(0,50),href:el.getAttribute('href')})});"
            "return JSON.stringify(out);"
            "})()"
        )
        return self._cdp_eval(tab["ws"], js)

    def verify_xss(self, url, index=0, wait=4):
        """黑盒 XSS 验证：导航到带 payload 的 URL，检测 alert 弹窗是否触发。

        返回结构化三态结果（json 字符串）：
        - status: CONFIRMED / INCONCLUSIVE / NOT_CONFIRMED
        - evidence: 实际观察到的证据
        - reason: 判定理由
        - scope: 本次验证覆盖的输入 / 上下文 / 执行路径

        当前黑盒路径只产出 CONFIRMED（alert 触发）和 INCONCLUSIVE（未触发）。
        NOT_CONFIRMED 需读响应源码判断转义，第一周不实现，语义预留。
        alert 触发（javascriptDialogOpening）即说明 payload 的 JS 真的执行了。
        """
        if not _HAS_WS:
            raise CDPError("缺少 websocket-client")
        tab = self._get_tab(index)
        ws = websocket.create_connection(tab["ws"], timeout=wait + 8)
        try:
            # 订阅 Page 事件（为了收到 javascriptDialogOpening）
            ws.send(json.dumps({"id": 1, "method": "Page.enable", "params": {}}))
            while True:
                msg = json.loads(ws.recv())
                if msg.get("id") == 1:
                    break
            # 导航到带 payload 的 URL（触发 XSS）
            ws.send(json.dumps({"id": 2, "method": "Page.navigate", "params": {"url": url}}))
            # 监听 javascriptDialogOpening 事件
            deadline = time.time() + wait
            dialog = None
            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ws.settimeout(remaining)
                try:
                    msg = json.loads(ws.recv())
                except Exception:
                    break
                if msg.get("method") == "Page.javascriptDialogOpening":
                    dialog = msg.get("params", {}).get("message", "")
                    # 关闭弹窗，避免页面阻塞
                    ws.send(json.dumps({"id": 99, "method": "Page.handleJavaScriptDialog",
                                        "params": {"accept": True}}))
                    break
            if dialog is not None:
                result = {
                    "status": "CONFIRMED",
                    "evidence": f"观察到 Page.javascriptDialogOpening，dialog 消息: {dialog}",
                    "reason": "alert 弹窗触发，说明注入的 JS 在该执行路径上真的执行了",
                    "scope": f"URL: {url}",
                }
            else:
                result = {
                    "status": "INCONCLUSIVE",
                    "evidence": "导航完成，wait 窗口内未观察到 javascriptDialogOpening",
                    "reason": "alert 未触发不能排除 XSS：可能 CSP 拦截 / 上下文不符 / payload 不合适 / 事件未触发",
                    "scope": f"URL: {url}（黑盒验证，未读响应源码，故不判 NOT_CONFIRMED）",
                }
            return json.dumps(result, ensure_ascii=False)
        finally:
            ws.close()

    def read_page_text(self, tab, timeout=10):
        """读某 tab 的可见文本（innerText）。"""
        ws_url = tab.get("ws")
        if not ws_url:
            raise CDPError("该 tab 没有 webSocketDebuggerUrl")
        return self._cdp_eval(ws_url, "document.body ? document.body.innerText : ''", timeout)

    def read_page_html(self, tab, timeout=10):
        """读某 tab 的完整 DOM HTML（outerHTML）。"""
        ws_url = tab.get("ws")
        if not ws_url:
            raise CDPError("该 tab 没有 webSocketDebuggerUrl")
        return self._cdp_eval(ws_url, "document.documentElement.outerHTML", timeout)


def _wsl_to_windows_path(path):
    """把 WSL 路径 /mnt/c/... 转成 Windows 路径 C:\\..."""
    p = str(path)
    if p.startswith("/mnt/") and len(p) > 6:
        drive = p[5:6].upper()
        rest = p[6:]
        return f"{drive}:{rest}".replace("/", "\\")
    return p.replace("/", "\\")


def find_launcher():
    """找 cdp_launcher.exe（HackMate 项目目录下）。"""
    base = app_root()  # HackMate 根目录
    for rel in ("tools/cdp/launcher/cdp_launcher.exe",):
        p = base / rel
        if p.exists():
            return str(p)
    return None


def _find_chrome():
    """跨平台找 Chrome 可执行文件路径。"""
    import shutil
    for name in ("google-chrome", "chromium", "chromium-browser", "google-chrome-stable"):
        p = shutil.which(name)
        if p:
            return p
    mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if Path(mac).exists():
        return mac
    for c in (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Chromium\Application\chrome.exe",
    ):
        if Path(c).exists():
            return c
    return None


def _cleanup_wsl_cdp():
    """WSL：kill 所有 cdp_launcher + 调试 Chrome（清多实例，启动前必调）。"""
    cmd = (
        "Get-Process -Name cdp_launcher -ErrorAction SilentlyContinue | Stop-Process -Force; "
        "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | "
        "Where-Object { $_.CommandLine -match 'remote-debugging-port' } | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
    )
    try:
        subprocess.run(["powershell.exe", "-Command", cmd], capture_output=True, timeout=20)
    except Exception:
        pass


def launch_chrome(port=9222):
    """跨平台启动调试 Chrome。返回 True 表示已触发。

    - Windows（原生 + WSL）：有 cdp_launcher.exe，走 proxy（清多实例后启动）。
    - Linux / macOS：没有 cdp_launcher.exe，直接 chrome --remote-debugging-port。
    """
    launcher = find_launcher()
    if launcher:  # Windows：用 cdp_launcher.exe proxy
        _cleanup_wsl_cdp()  # kill 旧 cdp_launcher + 调试 Chrome（清多实例）
        time.sleep(2)
        win_path = _wsl_to_windows_path(launcher)
        try:
            subprocess.Popen(
                ["powershell.exe", "-Command", f"Start-Process '{win_path}'"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        except (FileNotFoundError, OSError):
            return False
    # Linux / macOS：直接 chrome
    chrome = _find_chrome()
    if not chrome:
        return False
    try:
        subprocess.Popen(
            [chrome, f"--remote-debugging-port={port}", "--remote-allow-origins=*",
             f"--user-data-dir={Path.home() / '.hackmate-chrome'}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except (FileNotFoundError, OSError):
        return False


def wait_for_cdp(host, port, timeout=25):
    """等待 CDP 就绪（轮询 /json/version）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://{host}:{port}/json/version", timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def resolve_cdp_host(host="localhost"):
    """解析 CDP host：WSL 环境下 localhost 需换成 WSL 网关 IP（否则连不到 Windows 的 Chrome proxy）。

    Windows / Linux 原生：/proc/version 不含 microsoft/wsl，返回原 host（localhost 正确）。
    WSL：检测到则解析 `ip route show default` 的网关 IP（如 172.27.64.1）。
    """
    if host not in ("localhost", "127.0.0.1", "::1"):
        return host  # 用户已显式配置非 localhost，尊重之
    try:
        with open("/proc/version", "r") as f:
            ver = f.read().lower()
        if "microsoft" in ver or "wsl" in ver:
            import subprocess
            out = subprocess.run(["ip", "route", "show", "default"],
                                 capture_output=True, text=True, timeout=5).stdout
            parts = out.split()
            if "via" in parts:
                gw = parts[parts.index("via") + 1]
                if gw:
                    return gw
    except Exception:
        pass
    return host


def ensure_cdp(host, port, auto_launch=True, timeout=25):
    """确保 CDP 就绪；没开则自动拉起 cdp_launcher 并等待。返回 CDPClient 或 None。"""
    host = resolve_cdp_host(host)  # WSL 环境 localhost → 网关 IP
    c = CDPClient(host, port)
    try:
        c._get_json("/json/version")
        return c
    except CDPError:
        pass

    if auto_launch and launch_chrome():
        print("[cdp] 已触发 Chrome 启动，等待 CDP 就绪（如弹 UAC/MessageBox 请点确认）...")
        if wait_for_cdp(host, port, timeout):
            print("[cdp] CDP 已就绪")
            return c
        print("[cdp] 等待超时，CDP 仍未就绪")

    return None


def watch(host="localhost", port=9222, interval=2.0):
    """周期性同步：列出 tab，变化时刷新输出。Ctrl+C 退出。"""
    c = CDPClient(host, port)
    prev = None
    print(f"[cdp] 监控 {host}:{port}，每 {interval}s 刷新，Ctrl+C 退出", flush=True)
    while True:
        try:
            tabs = c.list_tabs()
        except CDPError as e:
            print(f"[cdp] {e}", flush=True)
            time.sleep(interval)
            continue
        snapshot = [(t["id"], t["url"], t["title"]) for t in tabs]
        if snapshot != prev:
            print(f"\n=== 当前 Chrome 页面 ({len(tabs)}) ===", flush=True)
            for i, t in enumerate(tabs):
                mark = "●" if i == 0 else "○"
                print(f"  {mark} {t['title']}\n      {t['url']}", flush=True)
            prev = snapshot
        time.sleep(interval)


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="CDP 只读监视（列出/同步/读页面内容）")
    p.add_argument("command", choices=["list", "watch", "read", "html"], nargs="?", default="watch")
    p.add_argument("index", type=int, nargs="?", default=0)
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=9222)
    p.add_argument("--interval", type=float, default=2.0)
    args = p.parse_args()

    c = CDPClient(args.host, args.port)
    if args.command in ("read", "html"):
        tabs = c.list_tabs()
        if not tabs:
            print("[cdp] 没有页面 tab")
            raise SystemExit(1)
        if not (0 <= args.index < len(tabs)):
            print(f"[cdp] 序号 {args.index} 超出范围（0-{len(tabs)-1}）")
            raise SystemExit(1)
        tab = tabs[args.index]
        content = c.read_page_text(tab) if args.command == "read" else c.read_page_html(tab)
        label = "可见文本" if args.command == "read" else "DOM HTML"
        print(f"=== [{tab['title']}] {label}（{len(content)} 字符）===")
        print(content)
    elif args.command == "list":
        tabs = c.list_tabs()
        print(f"=== 当前 Chrome 页面 ({len(tabs)}) ===")
        for i, t in enumerate(tabs):
            print(f"[{i}] {t['title']}  |  {t['url']}")
    else:
        try:
            watch(args.host, args.port, args.interval)
        except KeyboardInterrupt:
            print("\n[cdp] 已停止")
