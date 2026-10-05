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

        返回 {"xss": bool, "dialog": str}。alert 触发（javascriptDialogOpening）即说明
        payload 的 JS 真的执行了 → XSS 成立。
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
            return json.dumps({"xss": dialog is not None, "dialog": dialog or ""}, ensure_ascii=False)
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
    base = Path(__file__).resolve().parent.parent  # HackMate 根目录
    for rel in ("cdp_tools/cdp_launcher.exe", "tool/cdp_tools/cdp_launcher.exe"):
        p = base / rel
        if p.exists():
            return str(p)
    return None


def launch_cdp():
    """启动 cdp_launcher.exe（Windows/WSL）。返回 True 表示已触发。"""
    launcher = find_launcher()
    if not launcher:
        return False
    win_path = _wsl_to_windows_path(launcher)
    try:
        subprocess.Popen(
            ["powershell.exe", "-Command", f"Start-Process '{win_path}'"],
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


def ensure_cdp(host, port, auto_launch=True, timeout=25):
    """确保 CDP 就绪；没开则自动拉起 cdp_launcher 并等待。返回 CDPClient 或 None。"""
    c = CDPClient(host, port)
    try:
        c._get_json("/json/version")
        return c
    except CDPError:
        pass

    if auto_launch and launch_cdp():
        print("[cdp] 已触发 cdp_launcher，等待 CDP 就绪（如弹 UAC/MessageBox 请点确认）...")
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
