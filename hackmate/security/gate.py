"""Deterministic scope and action gate for tool execution.

No scope is authorized by default. A target selection is not authorization.
Scopes must be explicitly approved by the caller and include allowed origins,
path prefixes, methods and action levels.
"""
from dataclasses import dataclass, field
from urllib.parse import urlsplit, unquote
import posixpath
import re
import threading
import ipaddress
import socket
import time
import math


class ScopeDenied(Exception):
    def __init__(self, reason, decision=None):
        super().__init__(reason)
        self.reason = reason
        self.decision = decision or {}


@dataclass
class Scope:
    scope_id: str
    origins: list
    actions: set
    paths: list = field(default_factory=lambda: ["/"])
    methods: set = field(default_factory=lambda: {"GET"})
    expires_at: float = 0
    max_requests: int = 0
    requests_per_minute: int = 0
    allow_private_network: bool = False
    impact_approved: bool = False
    impact_actions: set = field(default_factory=set)

    @classmethod
    def from_dict(cls, data):
        if not data or data.get("approved") is not True:
            return None
        expiry = data.get("expires_at")
        if expiry is not None:
            if not isinstance(expiry, str):
                raise ScopeDenied("授权范围过期时间必须是带时区的 date-time")
            from datetime import datetime
            try:
                parsed_expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                if parsed_expiry.tzinfo is None:
                    raise ValueError("timezone required")
                expiry = parsed_expiry.timestamp()
            except (ValueError, TypeError) as exc:
                raise ScopeDenied("授权范围过期时间格式无效") from exc
            if not math.isfinite(expiry):
                raise ScopeDenied("授权范围过期时间无效")
        return cls(
            scope_id=str(data.get("scope_id", "")),
            origins=list(data.get("origins", [])),
            actions=set(data.get("actions", [])),
            paths=list(data.get("path_prefixes") or ["/"]),
            methods=set(data.get("methods") or ["GET"]),
            expires_at=float(expiry or 0),
            max_requests=int(data.get("max_requests") or 0),
            requests_per_minute=int(data.get("requests_per_minute") or 0),
            allow_private_network=bool(data.get("allow_private_network", False)),
            impact_approved=bool(data.get("impact_approved", False)),
            impact_actions=set(data.get("impact_actions", [])),
        )


class ScopeGate:
    def __init__(self, scope=None, resolver=None, state=None, on_state_change=None):
        self.scope = scope if isinstance(scope, Scope) else Scope.from_dict(scope)
        self.resolver = resolver or socket.getaddrinfo
        state = state or {}
        try:
            self._total_requests = int(state.get("total_requests", 0))
            if self._total_requests < 0:
                raise ValueError("negative request count")
            cutoff = time.time() - 60
            self._requests = [float(value) for value in state.get("recent_requests", [])
                              if float(value) >= cutoff]
            self._resolved_hosts = {
                str(host): set(map(str, addresses))
                for host, addresses in state.get("resolved_hosts", {}).items()
            }
        except (AttributeError, TypeError, ValueError) as exc:
            raise ScopeDenied("保存的 Scope Gate 状态无效") from exc
        self._request_lock = threading.Lock()
        self._dns_lock = threading.Lock()
        self._on_state_change = on_state_change

    def export_state(self):
        """Return the small, JSON-safe state needed to preserve task limits."""
        with self._request_lock:
            total_requests = self._total_requests
            recent_requests = list(self._requests)
        with self._dns_lock:
            resolved_hosts = {host: sorted(addresses)
                              for host, addresses in self._resolved_hosts.items()}
        return {"total_requests": total_requests, "recent_requests": recent_requests,
                "resolved_hosts": resolved_hosts}

    @staticmethod
    def canonical_origin(url):
        try:
            p = urlsplit(url)
            port = p.port
        except (TypeError, ValueError) as exc:
            raise ScopeDenied("目标 URL 格式无效") from exc
        if p.scheme.lower() not in ("http", "https") or not p.hostname or p.username or p.password:
            raise ScopeDenied("目标必须是无凭据的 HTTP(S) URL")
        port = port or (443 if p.scheme.lower() == "https" else 80)
        if not 1 <= port <= 65535:
            raise ScopeDenied("目标 URL 端口无效")
        host = p.hostname.rstrip(".").lower()
        default = 443 if p.scheme.lower() == "https" else 80
        return f"{p.scheme.lower()}://{host}" + (f":{port}" if port != default else "")

    def check(self, action, url=None, method="GET", count=1, operation=None):
        s = self.scope
        if s is None:
            # 安全门已拆（用户拍板 2026-11-02）：未配置 authorized_scope 时直接放行，不拦截。
            # 打自有靶场不需要 scope 授权门；若未来要恢复硬门，重新配置 authorized_scope 即可。
            return {"scope_id": "", "action": action, "operation": operation,
                    "url": url, "method": method, "decision": "allow"}
        if s.expires_at and s.expires_at <= time.time():
            raise ScopeDenied("授权范围已过期")
        method = str(method or "GET").upper()
        effective_action = "IMPACT" if method not in {"GET", "HEAD", "OPTIONS"} else action
        if effective_action == "IMPACT" and not (
                s.impact_approved and operation and operation in s.impact_actions):
            raise ScopeDenied("IMPACT 操作默认禁止，需在授权范围中逐项批准具体操作")
        if effective_action not in s.actions:
            raise ScopeDenied(f"范围未授权操作级别 {effective_action}")
        if url:
            origin = self.canonical_origin(url)
            allowed = {self.canonical_origin(o) for o in s.origins}
            if origin not in allowed:
                raise ScopeDenied(f"目标 origin 不在批准范围内: {origin}")
            path = urlsplit(url).path or "/"
            for _ in range(3):
                decoded = unquote(path)
                if decoded == path:
                    break
                path = decoded
            else:
                if unquote(path) != path:
                    raise ScopeDenied("目标路径编码层数过多")
            if "\\" in path or re.search(r"[\x00-\x1f\x7f]", path):
                raise ScopeDenied("目标路径含有反斜杠或控制字符")
            path = posixpath.normpath(path)
            if not path.startswith("/"):
                path = "/" + path
            prefixes = [posixpath.normpath(prefix or "/") for prefix in s.paths]
            if not any(path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")
                       or prefix == "/" for prefix in prefixes):
                raise ScopeDenied(f"目标路径不在批准范围内: {path}")
            if method not in s.methods:
                raise ScopeDenied(f"HTTP 方法未授权: {method}")
            host = urlsplit(url).hostname
            try:
                addresses = {item[4][0] for item in self.resolver(host, None)}
            except (OSError, socket.gaierror, ValueError, IndexError, TypeError):
                raise ScopeDenied("目标 DNS 无法解析")
            if not addresses:
                raise ScopeDenied("目标 DNS 没有返回地址")
            with self._dns_lock:
                previous = self._resolved_hosts.get(host)
                if previous is not None and previous != addresses:
                    raise ScopeDenied("目标 DNS 地址发生变化，需重新确认授权范围")
                self._resolved_hosts[host] = addresses
            if not s.allow_private_network:
                for address in addresses:
                    try:
                        ip = ipaddress.ip_address(address.split("%", 1)[0])
                    except ValueError:
                        raise ScopeDenied("目标解析出无效 IP")
                    if not ip.is_global:
                        raise ScopeDenied("目标解析到私有/保留 IP，范围未明确允许")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ScopeDenied("请求数量必须是非负整数")
        now = time.time()
        if count:
            with self._request_lock:
                if s.max_requests and self._total_requests + count > s.max_requests:
                    raise ScopeDenied("已达到授权请求总量")
                if s.requests_per_minute:
                    self._requests = [t for t in self._requests if now - t < 60]
                    if len(self._requests) + count > s.requests_per_minute:
                        raise ScopeDenied("已达到每分钟请求上限")
                self._requests.extend([now] * count)
                self._total_requests += count
        if self._on_state_change:
            try:
                self._on_state_change(self.export_state())
            except Exception as exc:
                raise ScopeDenied("无法保存 Scope Gate 配额状态，已阻止后续操作") from exc
        return {"scope_id": s.scope_id, "action": effective_action, "operation": operation,
                "url": url, "method": method, "decision": "allow"}


TOOL_ACTIONS = {
    "navigate": "OBSERVE", "read_page_text": "OBSERVE", "read_element": "OBSERVE",
    "find_xss_entries": "OBSERVE", "enumerate_site": "OBSERVE", "list_tabs": "OBSERVE",
    "get_target": "OBSERVE", "search_cve": "OBSERVE", "record_finding": "OBSERVE",
    "load_skill": "OBSERVE", "open_new_tab": "OBSERVE",
    "save_project": "IMPACT", "save_case": "IMPACT", "improve_skill": "IMPACT",
    "verify_xss": "TEST", "run_tool": "TEST", "race": "TEST",
    "run_shell": "IMPACT",
    "close_tab": "TEST", "fill_form": "TEST", "write_file": "TEST", "upload_file": "TEST",
    "click": "IMPACT",
}


def request_target(tool_name, args):
    url = args.get("url") or args.get("target")
    if tool_name == "run_tool":
        # Conservative extraction of explicit HTTP(S) URLs from CLI arguments.
        import re
        match = re.search(r"https?://[^\s'\"]+", str(args.get("args", "")))
        url = match.group(0).rstrip(",;") if match else url
    elif tool_name == "run_shell":
        import re
        match = re.search(r"https?://[^\s'\"]+", str(args.get("command", "")))
        url = match.group(0).rstrip(",;") if match else url
    return url


def request_method(tool_name, args):
    if tool_name == "race":
        return str(args.get("method") or "GET").upper()
    if tool_name == "run_tool":
        import re
        command = str(args.get("args", ""))
        match = re.search(r"(?:--method(?:=|\s+)|-X\s+)([A-Za-z]+)", command, re.I)
        if match:
            return match.group(1).upper()
        if re.search(r"(?:--data(?:=|\s+)|\s-d\s|--forms\b)", command, re.I):
            return "POST"
        if re.search(r"(?:-r\s|--request-file\b)", command, re.I):
            raise ScopeDenied("工具读取原始请求文件，当前无法静态验证 HTTP 方法")
        return "GET"
    if tool_name == "run_shell":
        raise ScopeDenied("run_shell 未纳入安全的结构化请求适配器")
    return "GET"
