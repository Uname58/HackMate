"""HackMate MCP 客户端 —— stdio 传输，纯标准库（零依赖）。

接外部 MCP 服务器（如 jshookmcp），发现其工具并注册进 HackMate 工具表。
协议：JSON-RPC 2.0 over stdin/stdout，LSP 风格 Content-Length 分帧。
"""
import json
import os
import subprocess
import threading

SAFE_ENV = ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR")


class MCPClient:
    """一个 stdio MCP 服务器连接。connect() 后 .tools 为该服务器暴露的工具列表。"""

    def __init__(self, name, command, args=None, env=None, timeout=120):
        self.name = name
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.timeout = timeout
        self.proc = None
        self.tools = []
        self._id = 0
        self._lock = threading.Lock()

    # ---- 连接 ----
    def connect(self):
        env = {k: os.environ[k] for k in SAFE_ENV if k in os.environ}
        env.update(self.env)
        self.proc = subprocess.Popen(
            [self.command] + self.args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, encoding="utf-8",
        )
        self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "hackmate", "version": "4.0.0"},
        })
        self._notify("notifications/initialized", {})
        self.tools = self._request("tools/list", {}).get("tools", [])
        return self.tools

    # ---- JSON-RPC 传输 ----
    def _send(self, payload):
        data = json.dumps(payload, ensure_ascii=False)
        frame = f"Content-Length: {len(data.encode('utf-8'))}\r\n\r\n{data}"
        self.proc.stdin.write(frame)
        self.proc.stdin.flush()

    def _recv(self):
        headers = {}
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"MCP server '{self.name}' 关闭了 stdout")
            line = line.strip()
            if not line:
                break
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0"))
        return json.loads(self.proc.stdout.read(length))

    def _request(self, method, params):
        with self._lock:
            self._id += 1
            rid = self._id
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            while True:
                msg = self._recv()
                if msg.get("id") == rid:
                    if "error" in msg:
                        raise RuntimeError(f"MCP error: {msg['error']}")
                    return msg.get("result", {})
                # 非本请求的消息（server 通知）忽略

    def _notify(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    # ---- 调用 ----
    def call(self, name, arguments):
        with self._lock:
            self._id += 1
            rid = self._id
            self._send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                        "params": {"name": name, "arguments": arguments}})
            while True:
                msg = self._recv()
                if msg.get("id") == rid:
                    if "error" in msg:
                        return f"（MCP 调用失败：{msg['error']}）"
                    result = msg.get("result", {})
                    content = result.get("content", [])
                    texts = [c.get("text", "") for c in content if c.get("type") == "text"]
                    return "\n".join(texts) if texts else json.dumps(result, ensure_ascii=False)

    def close(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()
