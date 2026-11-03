"""Contract-bound role adapters for the five-agent workflow.

Each LLM role gets a fresh context and must return one JSON object. Tool
execution stays in Python and is limited by the workflow and shared gate.
"""
import json
import math
import re
import uuid
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit
from datetime import datetime, timezone

from ..schema_validation import SCHEMA_DIR, validate

_SCHEMAS = {
    "recon": "recon_result.schema.json",
    "analyze": "analyze_result.schema.json",
    "attacker": "attacker_result.schema.json",
    "reporter": "reporter_result.schema.json",
}
_PROMPTS = {
    "recon": "Collect facts only. Do not decide whether a vulnerability exists. Return JSON matching the supplied schema. Distinguish observed facts from unknowns and attach evidence refs.",
    "analyze": "Analyze supplied reconnaissance facts. Produce hypotheses and ordered, bounded test steps. A hypothesis is not a finding. Do not call tools. Return JSON matching the schema.",
    "attacker": "Execute only the supplied plan. You are in a bounded feedback loop: return at most one tool_request for this turn, then use prior_attempts to choose the next step. Set tool_request to null when finished. Never claim confirmation without an observed tool result. No rescanning, out-of-plan tools, or scope changes.",
    "reporter": "Independently review the raw evidence supplied below, not merely the Attacker conclusion. Check target/input linkage, reproducibility, impact and false-positive explanations. Return finding details and concrete reproduction steps. Leave finding null and CVSS null when evidence is insufficient.",
}
ATTACK_ADAPTERS = {
    # First vertical slice. Add other vulnerability families only with their own
    # bounded tool capabilities, playbooks, evidence rules and Eval coverage.
    "reflected_xss": {
        "aliases": {"reflected_xss", "reflected-xss"},
        "tools": {"navigate", "read_page_text", "read_element", "find_xss_entries", "verify_xss"},
    },
}
_SECRET_FIELD = re.compile(
    r"^(?:authorization|proxy.authorization|cookie|set.cookie|x.api.key|api.key|token|"
    r"auth.token|jwt|"
    r"access.token|refresh.token|id.token|client.secret|password|passwd|secret|"
    r"session(?:id|_id)?|csrf(?:token|_token)?)$", re.I)
_SECRET_HEADER = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|api-key|x-auth-token)\s*:\s*).+$")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)([\"']?(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|"
    r"api-key|x-auth-token|access_token|refresh_token|id_token|client_secret|api_key|"
    r"auth_token|token|jwt|(?:user_)?password|passwd|session_id|csrf_token)"
    r"[\"']?\s*[:=]\s*[\"']?)[^\s\"'&,;}]+")
_SECRET_JSON_VALUE = re.compile(
    r"(?i)([\"'](?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|"
    r"api-key|x-auth-token)[\"']\s*:\s*[\"'])[^\"']*([\"'])")
_SECRET_QUERY = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|token|api[_-]?key|password|passwd|"
    r"session(?:id|_id)?|auth|secret)=)[^&#\s]+")
_SECRET_HTML = re.compile(
    r"(?is)(\bname\s*=\s*(['\"]?)(?:access_token|refresh_token|api_key|"
    r"password|passwd|session_id|csrf_token)\2[^>]*?\bvalue\s*=\s*(['\"]?))"
    r"[^\s>\"']+")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")


def redact_for_model(value):
    """Return a sanitized copy for LLM prompts; the evidence store stays raw.

    The deterministic evidence repository retains original bytes for independent
    review. This function only limits accidental credential disclosure to the
    model provider and never mutates the stored artifact.
    """
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if _SECRET_FIELD.fullmatch(str(key)) else redact_for_model(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_for_model(item) for item in value]
    if isinstance(value, tuple):
        return [redact_for_model(item) for item in value]
    if not isinstance(value, str):
        return value
    value = _SECRET_HEADER.sub(r"\1[REDACTED]", value)
    value = _SECRET_JSON_VALUE.sub(r"\1[REDACTED]\2", value)
    value = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    value = _SECRET_QUERY.sub(r"\1[REDACTED]", value)
    value = _SECRET_HTML.sub(r"\1[REDACTED]", value)
    value = _BEARER.sub(r"\1 [REDACTED]", value)
    return value


def select_attack_adapter(analysis, hypothesis_id):
    """Resolve one Analyze hypothesis to a currently implemented test adapter."""
    hypothesis = next((item for item in analysis.get("hypotheses", [])
                       if item.get("hypothesis_id") == hypothesis_id), None)
    if hypothesis is None:
        return None, "Attacker 引用的 hypothesis_id 不存在于 Analyze 结果"
    kind = str(hypothesis.get("type", "")).strip().lower().replace(" ", "_")
    for adapter_name, adapter in ATTACK_ADAPTERS.items():
        if kind in adapter["aliases"]:
            return adapter, ""
    return None, f"漏洞类型 {kind or 'unknown'} 暂无 Attacker 执行适配器"


def validate_attacker_request(analysis, adapter, tool_name):
    """Require every execution to be both adapter-supported and Analyze-planned."""
    if tool_name not in adapter.get("tools", set()):
        raise ValueError(f"Attacker requested tool outside selected adapter allowlist: {tool_name}")
    planned = {tool for step in analysis.get("test_plan", [])
               for tool in step.get("tool_capabilities", [])}
    if tool_name not in planned:
        raise ValueError(f"Attacker requested tool not named in Analyze test plan: {tool_name}")
    return True


def _event_contains_dialog(value):
    if isinstance(value, dict):
        if value.get("method") == "Page.javascriptDialogOpening":
            return True
        return any(_event_contains_dialog(item) for item in value.values())
    if isinstance(value, list):
        return any(_event_contains_dialog(item) for item in value)
    return False


def _same_endpoint_path(left, right):
    try:
        a, b = urlsplit(left), urlsplit(right)
        default_a = 443 if a.scheme.lower() == "https" else 80
        default_b = 443 if b.scheme.lower() == "https" else 80
        return ((a.scheme.lower(), (a.hostname or "").lower(), a.port or default_a,
                 a.path.rstrip("/") or "/") ==
                (b.scheme.lower(), (b.hostname or "").lower(), b.port or default_b,
                 b.path.rstrip("/") or "/"))
    except ValueError:
        return False


def _reporter_xss_evidence_is_sufficient(report, attacker, analysis, evidence):
    """Require raw same-input HTTP and browser-execution evidence for XSS accepts."""
    finding = report.get("finding") or {}
    hypothesis = next((item for item in analysis.get("hypotheses", [])
                       if item.get("hypothesis_id") == attacker.get("hypothesis_id")), None)
    expected_type = str((hypothesis or {}).get("type", "")).lower().replace("-", "_")
    finding_type = str(finding.get("type", "")).lower().replace("-", "_")
    if expected_type not in {"reflected_xss", "reflectedxss"} or finding_type != expected_type:
        return False, "Reporter finding type does not match the selected XSS hypothesis"
    if attacker.get("result") != "CONFIRMED":
        return False, "Attacker did not observe a confirmed browser execution signal"

    reviewed = set(report.get("evidence_reviewed", []))
    references = set(report.get("evidence_refs", []))
    linked = [item for item in evidence
              if item["metadata"]["evidence_id"] in reviewed & references]
    requests = [item for item in linked if item["metadata"].get("kind") == "http_request"]
    responses = [item for item in linked if item["metadata"].get("kind") == "http_response"]
    events = [item for item in linked if item["metadata"].get("kind") == "cdp_event"]
    endpoint = finding.get("endpoint") or ""
    parameter = str(finding.get("parameter") or "")
    matching_inputs = set()
    for item in requests:
        try:
            entries = json.loads(item.get("raw_content", ""))
        except (json.JSONDecodeError, TypeError):
            continue
        for entry in entries if isinstance(entries, list) else []:
            request = entry.get("params", {}).get("request", {}) if isinstance(entry, dict) else {}
            request_url = request.get("url", "")
            query = dict(parse_qsl(urlsplit(request_url).query, keep_blank_values=True))
            if _same_endpoint_path(request_url, endpoint) and parameter in query:
                matching_inputs.add(query[parameter])
    response_matches = False
    for item in responses:
        try:
            entries = json.loads(item.get("raw_content", ""))
        except (json.JSONDecodeError, TypeError):
            continue
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            response = entry.get("params", {}).get("response", {})
            response_url = response.get("url") or entry.get("url", "")
            response_query = dict(parse_qsl(urlsplit(response_url).query, keep_blank_values=True))
            if (_same_endpoint_path(response_url, endpoint) and parameter in response_query and
                    response_query[parameter] in matching_inputs):
                response_matches = True
                break
        if response_matches:
            break
    dialog_seen = False
    for item in events:
        try:
            dialog_seen = dialog_seen or _event_contains_dialog(json.loads(item.get("raw_content", "")))
        except (json.JSONDecodeError, TypeError):
            continue
    if not matching_inputs:
        return False, "Reporter accept lacks a reviewed HTTP request containing the reported endpoint and parameter"
    if not response_matches:
        return False, "Reporter accept lacks a reviewed HTTP response from the reported endpoint"
    if not dialog_seen:
        return False, "Reporter accept lacks a raw CDP JavaScript execution event"
    return True, ""


def _load_schema(name):
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def adapt_enumerate_site(task, raw_facts, evidence_ref):
    """Convert the existing one-page CDP inventory into explicit Recon facts."""
    base_url = task["target"]["base_url"]
    base = urlsplit(base_url)
    base_port = base.port or (443 if base.scheme.lower() == "https" else 80)
    base_origin = (base.scheme.lower(), (base.hostname or "").rstrip(".").lower(), base_port)

    def same_origin_url(value, current=base_url):
        if not isinstance(value, str) or not value.strip():
            return None
        candidate = urlsplit(urljoin(current, value.strip()))
        try:
            port = candidate.port or (443 if candidate.scheme.lower() == "https" else 80)
            origin = (candidate.scheme.lower(), (candidate.hostname or "").rstrip(".").lower(), port)
        except ValueError:
            return None
        if candidate.scheme.lower() not in {"http", "https"} or origin != base_origin:
            return None
        return urlunsplit((candidate.scheme, candidate.netloc, candidate.path or "/",
                           candidate.query, ""))

    if isinstance(raw_facts, str):
        try:
            source = json.loads(raw_facts)
        except (json.JSONDecodeError, TypeError):
            source = {"unparsed_output": raw_facts}
    elif isinstance(raw_facts, dict):
        source = raw_facts
    else:
        source = {"unparsed_output": str(raw_facts)}

    observed_url = same_origin_url(source.get("url")) or base_url
    endpoints = {}

    def endpoint_for(value, method="GET"):
        endpoint_url = same_origin_url(value)
        if endpoint_url is None:
            return None
        method = str(method or "GET").upper()
        key = (endpoint_url, method)
        if key not in endpoints:
            endpoints[key] = {"url": endpoint_url, "method": method, "parameters": [],
                              "evidence_refs": [evidence_ref]}
        return endpoints[key]

    def add_parameter(endpoint, name, location):
        if endpoint is None or not isinstance(name, str) or not name:
            return
        item = {"name": name, "location": location}
        if item not in endpoint["parameters"]:
            endpoint["parameters"].append(item)

    base_endpoint = endpoint_for(observed_url)
    for name, _value in parse_qsl(urlsplit(observed_url).query, keep_blank_values=True):
        add_parameter(base_endpoint, name, "query")
    for name in source.get("url_params", []) if isinstance(source.get("url_params"), list) else []:
        add_parameter(base_endpoint, name, "query")

    for collection in ("links", "api_endpoints"):
        values = source.get(collection, [])
        if not isinstance(values, list):
            continue
        for value in values:
            endpoint = endpoint_for(value)
            if endpoint:
                for name, _item in parse_qsl(urlsplit(endpoint["url"]).query, keep_blank_values=True):
                    add_parameter(endpoint, name, "query")

    form_field_names = set()
    forms = source.get("forms", [])
    if isinstance(forms, list):
        for form in forms:
            if not isinstance(form, dict):
                continue
            endpoint = endpoint_for(form.get("action") or observed_url, form.get("method", "GET"))
            fields = form.get("fields", [])
            if not isinstance(fields, list):
                continue
            for field in fields:
                if isinstance(field, dict):
                    name = field.get("name")
                    if name:
                        form_field_names.add(name)
                        add_parameter(endpoint, name, "form")

    # Keep visible controls that are not associated with a submitted form as
    # observations, without claiming that they are request parameters.
    for collection in ("inputs", "textareas", "selects"):
        values = source.get(collection, [])
        if not isinstance(values, list):
            continue
        for control in values:
            name = control.get("name") if isinstance(control, dict) else None
            if name and name not in form_field_names:
                add_parameter(base_endpoint, name, "unknown")

    limitations = ["现有 enumerate_site 只检查单个页面；不会递归爬站或提交表单。"]
    if "unparsed_output" in source:
        limitations.append("枚举工具输出不是可解析的 JSON，保留为原始观察供 Analyze 判断。")
    if source.get("status") == "BLOCKED":
        endpoints.clear()
        limitations.append("枚举请求被 Scope Gate 阻止，未观察到端点或参数。")

    return {"target": task["target"], "technologies": [], "infrastructure": [],
            "endpoints": list(endpoints.values()), "authentication": "unknown",
            "observations": [{"value": source, "confidence": "observed",
                              "evidence_refs": [evidence_ref]}],
            "evidence_refs": [evidence_ref], "limitations": limitations}


class JsonRole:
    def __init__(self, client, role, schema_name=None, budget=None, max_retries=1):
        self.client = client
        self.role = role
        self.schema = _load_schema(schema_name or _SCHEMAS[role])
        self.budget = budget
        self.max_retries = max(0, min(2, int(max_retries)))

    def ask(self, data):
        repair = ""
        last_error = None
        for attempt in range(self.max_retries + 1):
            prompt = (f"ROLE: {self.role}\nCONTRACT: {json.dumps(self.schema, ensure_ascii=False)}\n"
                      f"INPUT: {json.dumps(redact_for_model(data), ensure_ascii=False, default=str)}\n"
                      f"REPAIR FEEDBACK: {repair}\n"
                      "Return only one valid JSON object; no markdown fences or prose.")
            role_client = self.client.clone(system_prompt=_PROMPTS[self.role])
            if hasattr(role_client, "max_retries"):
                # JsonRole owns the task-scoped retry count and charges failed attempts
                # against TokenBudget instead of nesting an unaccounted HTTP retry loop.
                role_client.max_retries = 0
            if getattr(self, "cancel_event", None) is not None:
                role_client.set_cancel_event(self.cancel_event)
            if self.budget:
                role_client.max_output_tokens = self.budget.before(prompt)
            try:
                raw = role_client.ask(prompt)
            except Exception as exc:
                retryable = (getattr(exc, "retryable", False) or
                             isinstance(exc, (TimeoutError, ConnectionError)))
                if not retryable:
                    raise
                last_error = exc
                if self.budget:
                    # A failed request may still have consumed provider input tokens.
                    self.budget.after(prompt, "", None)
                if attempt >= self.max_retries:
                    raise
                repair = f"上一轮模型连接失败（可重试）：{type(exc).__name__}: {exc}"
                continue
            if self.budget:
                self.budget.after(prompt, raw, role_client.last_usage)
            try:
                result = json.loads(raw)
                validate(result, self.schema)
                return result
            except (json.JSONDecodeError, ValueError) as exc:
                last_error = exc
                repair = (f"上一条输出未通过 JSON/Schema 校验：{exc}. Previous output: "
                          f"{redact_for_model(raw)[:4000]}")
        raise ValueError(f"{self.role} output invalid after {self.max_retries + 1} attempts: {last_error}")


class TokenBudget:
    def __init__(self, max_tokens=0, on_usage=None, initial_tokens=0):
        self.max_tokens = int(max_tokens or 0)
        self.total = int(initial_tokens or 0)
        self.mode = "reported"
        self.on_usage = on_usage

    @staticmethod
    def estimate(text):
        return max(1, math.ceil(len(text.encode("utf-8")) / 4))

    def before(self, prompt):
        estimate = self.estimate(prompt)
        if self.max_tokens and self.total + estimate + 64 > self.max_tokens:
            raise RuntimeError("token budget exhausted before agent call")
        return max(1, min(2048, self.max_tokens - self.total - estimate)) if self.max_tokens else 2048

    def after(self, prompt, response, usage):
        if isinstance(usage, dict) and isinstance(usage.get("total_tokens"), int):
            tokens = usage["total_tokens"]
        else:
            tokens = self.estimate(prompt) + self.estimate(response)
            self.mode = "estimated"
        self.total += tokens
        if self.on_usage:
            self.on_usage(tokens, self.mode)
        if self.max_tokens and self.total > self.max_tokens:
            raise RuntimeError("token budget exhausted after agent response")


def build_agent_adapters(client, tool_context, evidence_repo, task_id, recon_adapter=None,
                         max_tokens=0, usage_callback=None, cancel_event=None, max_retries=1,
                         initial_tokens=0):
    """Build role callables consumed by Orchestrator.

    Recon defaults to the existing ``enumerate_site`` tool. Attacker can only
    invoke the safe Reflected-XSS browser tools from a validated plan.
    """
    from ..tools import dispatch
    from ..security import ScopeGate
    budget = TokenBudget(max_tokens=max_tokens, on_usage=usage_callback, initial_tokens=initial_tokens)
    roles = {name: JsonRole(
        client, name,
        schema_name="attacker_action.schema.json" if name == "attacker" else _SCHEMAS[name],
        budget=budget, max_retries=max_retries) for name in _SCHEMAS}
    for role in roles.values():
        role.cancel_event = cancel_event
    active_gate = (tool_context.scope_gate
                   if tool_context.task_id == task_id and tool_context.scope_gate is not None
                   else None)

    def bind_task(task):
        nonlocal active_gate
        if task.get("task_id") != task_id:
            raise ValueError("agent adapter received a task outside its bound task id")
        if active_gate is None:
            active_gate = ScopeGate(task.get("scope"))
        tool_context.scope_gate = active_gate
        tool_context.evidence_repo = evidence_repo
        tool_context.task_id = task["task_id"]

    def recon(task, prior):
        bind_task(task)
        if recon_adapter:
            facts = recon_adapter(task, prior)
        else:
            raw_facts = dispatch("enumerate_site", {"url": task["target"]["base_url"]}, tool_context)
            ev = evidence_repo.put(task["task_id"], "tool_output", "recon", raw_facts,
                                   content_type="text/plain; charset=utf-8", redaction_status="pending")
            facts = adapt_enumerate_site(task, raw_facts, ev["evidence_id"])
        result = roles["recon"].ask({"task": task, "recon_facts": facts})
        available = {item["evidence_id"] for item in evidence_repo.list_task(task_id)}
        refs = set(result.get("evidence_refs", []))
        refs.update(ref for endpoint in result.get("endpoints", [])
                    for ref in endpoint.get("evidence_refs", []))
        refs.update(ref for observation in result.get("observations", [])
                    for ref in observation.get("evidence_refs", []))
        if not refs.issubset(available):
            raise ValueError("Recon referenced evidence that was not stored for this task")
        return result

    def analyze(task, prior):
        bind_task(task)
        return roles["analyze"].ask({"task": task, "recon": prior["recon"]})

    def attacker(task, prior):
        bind_task(task)
        analysis = prior["analyze"]
        previous_attack = prior.get("attacker", {})
        previous_attempts = list(previous_attack.get("attempts", []))
        previous_evidence_refs = list(previous_attack.get("evidence_refs", []))
        previous_execution_refs = list(previous_attack.get("execution_refs", []))
        action = roles["attacker"].ask({"task": task, "recon": prior["recon"],
                                         "analysis": analysis, "prior_attempts": [],
                                         "previous_attempts": previous_attempts,
                                         "remaining_rounds": task.get("budget", {}).get("max_attack_rounds", 3)})
        adapter, adapter_error = select_attack_adapter(analysis, action.get("hypothesis_id"))
        if adapter is None:
            result = {"test_id": "test_" + uuid.uuid4().hex[:12],
                      "hypothesis_id": action["hypothesis_id"], "execution_status": "blocked",
                      "payloads": [], "tool_requests": [], "attempts": [], "execution_refs": [],
                      "browser_events": [], "evidence_refs": [], "result": "BLOCKED",
                      "reason": adapter_error,
                      "limitations": list(action.get("limitations", [])) + [
                          "该漏洞类型尚无通过 Eval 的 Attacker 适配器"]}
            validate(result, _load_schema(_SCHEMAS["attacker"]))
            return result

        max_rounds = max(1, min(5, int(task.get("budget", {}).get("max_attack_rounds", 3) or 1)))
        test_id = "test_" + uuid.uuid4().hex[:12]
        hypothesis_id = action["hypothesis_id"]
        prior_attempts, attempts, tool_requests = [], [], []
        payloads = []
        evidence_refs = [ref for ref in previous_evidence_refs
                         if evidence_repo.get(ref).get("task_id") == task_id]
        execution_refs = [ref for ref in previous_execution_refs
                          if evidence_repo.get(ref).get("task_id") == task_id]
        browser_events = []
        statuses = []
        reason = action.get("reason", "")
        limitations = list(action.get("limitations", []))
        for round_index in range(max_rounds):
            if action.get("hypothesis_id") != hypothesis_id:
                raise ValueError("Attacker changed hypothesis during the bounded execution loop")
            request = action.get("tool_request")
            reason = action.get("reason") or reason
            limitations.extend(item for item in action.get("limitations", []) if item not in limitations)
            if request is None:
                break
            name, args = request.get("tool"), request.get("args", {})
            validate_attacker_request(analysis, adapter, name)
            tool_requests.append(request)
            sent_args = unquote(json.dumps(args, ensure_ascii=False))
            payloads.extend(item for item in action.get("payloads", [])
                            if item and item in sent_args and item not in payloads)
            raw = dispatch(name, args, tool_context)
            ev = evidence_repo.put(task["task_id"], "tool_output", "attacker", raw,
                                   content_type="text/plain; charset=utf-8", redaction_status="pending",
                                   metadata={"tool": name, "arguments": args})
            attempt_evidence_refs = [ev["evidence_id"]]
            try:
                tool_result = json.loads(raw)
                observed = tool_result.get("status", "INCONCLUSIVE")
                if observed not in {"CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE", "BLOCKED", "ERROR"}:
                    observed = "INCONCLUSIVE"
                browser_events.extend(json.dumps(item, ensure_ascii=False)
                                      for item in tool_result.get("browser_events", []))
                child_refs = [ref for ref in tool_result.get("evidence_refs", [])
                              if evidence_repo.get(ref).get("task_id") == task_id]
                attempt_evidence_refs.extend(child_refs)
            except (json.JSONDecodeError, AttributeError):
                observed = "ERROR" if raw.startswith("工具执行错误:") else "INCONCLUSIVE"
                tool_result = {"status": observed, "reason": raw}
            evidence_refs.extend(ref for ref in attempt_evidence_refs if ref not in evidence_refs)
            statuses.append(observed)

            from ..security import TOOL_ACTIONS, request_method
            action_level = TOOL_ACTIONS[name]
            if request_method(name, args) not in {"GET", "HEAD", "OPTIONS"}:
                action_level = "IMPACT"
            execution_record = {
                "execution_id": "exec_" + uuid.uuid4().hex,
                "task_id": task_id,
                "run_id": task.get("current_run_id"),
                "tool_name": name,
                "action_level": action_level,
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "gate_decision": "deny" if observed == "BLOCKED" else "allow",
                "gate_reason": tool_result.get("reason") if observed == "BLOCKED" else None,
                "status": ("blocked" if observed == "BLOCKED" else
                           "failed" if observed == "ERROR" else "completed"),
                "input_evidence_refs": list(prior["recon"].get("evidence_refs", [])),
                "evidence_refs": list(attempt_evidence_refs),
                "error": tool_result.get("reason") if observed in {"BLOCKED", "ERROR"} else None,
            }
            validate(execution_record, _load_schema("execution.schema.json"))
            execution_ev = evidence_repo.put(
                task_id, "execution_log", "attacker",
                json.dumps(execution_record, ensure_ascii=False),
                content_type="application/json", redaction_status="pending",
                metadata={"execution_id": execution_record["execution_id"], "tool_name": name})
            execution_refs.append(execution_ev["evidence_id"])
            attempt = {"attempt": round_index + 1, "tool_request": request,
                       "execution_ref": execution_ev["evidence_id"], "result": observed,
                       "evidence_refs": attempt_evidence_refs}
            attempts.append(attempt)
            prior_attempts.append({"attempt": round_index + 1, "tool_request": request,
                                   "result": observed, "result_detail": raw,
                                   "execution_ref": execution_ev["evidence_id"],
                                   "evidence_refs": attempt_evidence_refs})
            if observed in {"CONFIRMED", "BLOCKED", "ERROR"} or action.get("decision") in {"stop", "confirmed", "blocked"}:
                break
            if round_index + 1 >= max_rounds:
                break
            action = roles["attacker"].ask({"task": task, "recon": prior["recon"],
                                            "analysis": analysis, "prior_attempts": prior_attempts,
                                            "previous_attempts": previous_attempts,
                                            "remaining_rounds": max_rounds - round_index - 1})

        # Recon evidence remains available to Reporter; all other evidence refs
        # below are IDs created by this task's deterministic execution path.
        for ref in prior["recon"].get("evidence_refs", []):
            if evidence_repo.get(ref).get("task_id") == task_id and ref not in evidence_refs:
                evidence_refs.append(ref)
        if "CONFIRMED" in statuses:
            final_status = "CONFIRMED"
        elif "BLOCKED" in statuses:
            final_status = "BLOCKED"
        elif "ERROR" in statuses:
            final_status = "ERROR"
        elif statuses and all(status == "NOT_CONFIRMED" for status in statuses):
            final_status = "NOT_CONFIRMED"
        else:
            final_status = "INCONCLUSIVE"
        result = {
            "test_id": test_id, "hypothesis_id": hypothesis_id,
            "execution_status": ("blocked" if final_status == "BLOCKED" else
                                 "failed" if final_status == "ERROR" else
                                 "completed" if attempts else "partial"),
            "payloads": payloads, "tool_requests": tool_requests, "attempts": attempts,
            "execution_refs": execution_refs, "browser_events": browser_events,
            "evidence_refs": sorted(set(evidence_refs)), "result": final_status,
            "reason": reason or ("完成有界测试尝试" if attempts else "Analyze 计划未授权可执行工具"),
            "limitations": limitations,
        }
        validate(result, _load_schema(_SCHEMAS["attacker"]))
        return result

    def reporter(task, prior):
        bind_task(task)
        references = set(prior["attacker"].get("evidence_refs", []))
        evidence = []
        for item in evidence_repo.list_task(task["task_id"]):
            if item["evidence_id"] in references:
                if (item.get("content_type") or "").startswith("image/"):
                    content = "[binary screenshot artifact; this text-only Reporter cannot render it]"
                else:
                    try:
                        content = evidence_repo.read(item["evidence_id"]).decode("utf-8", "replace")[:24000]
                    except Exception as exc:
                        content = f"[unreadable evidence: {exc}]"
                evidence.append({"metadata": item, "raw_content": content[:100000]})
        result = roles["reporter"].ask({"task": task, "attacker_result": prior["attacker"],
                                         "independently_loaded_raw_evidence": evidence})
        available = {item["metadata"]["evidence_id"] for item in evidence}
        referenced = set(result.get("evidence_reviewed", [])) | set(result.get("evidence_refs", []))
        if not referenced.issubset(available):
            raise ValueError("Reporter referenced evidence that was not independently loaded")
        finding = result.get("finding")
        finding_incomplete = (not isinstance(finding, dict) or any(
            not finding.get(field) for field in ("type", "title", "endpoint", "impact")))
        if result.get("verdict") == "accepted" and (
                not result.get("evidence_reviewed") or not result.get("evidence_refs") or
                not set(result.get("evidence_refs", [])).issubset(set(result.get("evidence_reviewed", []))) or
                not result.get("false_positive_checks") or
                result.get("reproducibility") != "reproducible" or
                not result.get("reproduction_steps") or finding_incomplete):
            result["verdict"] = "needs_more_evidence"
            result["rejection_reason"] = "Accepted finding lacks independently reviewed evidence, repeatable steps, or false-positive checks"
        if result.get("verdict") == "accepted":
            sufficient, evidence_reason = _reporter_xss_evidence_is_sufficient(
                result, prior["attacker"], prior["analyze"], evidence)
            if not sufficient:
                result["verdict"] = "needs_more_evidence"
                result["rejection_reason"] = evidence_reason
        result["writeup_ref"] = None
        result["finding_ref"] = None
        if result.get("verdict") == "accepted":
            finding = result["finding"]
            finding_id = "finding_" + uuid.uuid4().hex
            markdown = _render_writeup(task, prior["attacker"], result, evidence, finding_id)
            writeup = evidence_repo.put(
                task["task_id"], "writeup", "reporter", markdown,
                content_type="text/markdown; charset=utf-8", redaction_status="best_effort",
                metadata={"finding_id": finding_id})
            finding_schema = _load_schema("finding.schema.json")
            finding_record = {
                "finding_id": finding_id,
                "task_id": task["task_id"],
                "hypothesis_id": prior["attacker"]["hypothesis_id"],
                "type": finding["type"],
                "title": finding["title"],
                "endpoint": finding["endpoint"],
                "parameter": finding["parameter"],
                "verdict": "accepted",
                "impact": finding["impact"],
                "cvss_score": result.get("cvss_score"),
                "cvss_vector": result.get("cvss_vector"),
                "evidence_refs": result["evidence_refs"],
                "writeup_ref": writeup["evidence_id"],
                "reviewer_run_id": task.get("current_run_id", "")}
            validate(finding_record, finding_schema)
            finding_artifact = evidence_repo.put(
                task["task_id"], "finding", "reporter", json.dumps(finding_record, ensure_ascii=False),
                content_type="application/json", redaction_status="pending",
                metadata={"finding_id": finding_id})
            result["writeup_ref"] = writeup["evidence_id"]
            result["finding_ref"] = finding_artifact["evidence_id"]
        return result

    return {"recon": recon, "analyze": analyze, "attacker": attacker, "reporter": reporter}


def _render_writeup(task, attacker, report, evidence, finding_id):
    """Render a local report from Reporter-reviewed facts and sanitized excerpts."""
    finding = report["finding"]
    clean = lambda value: str(redact_for_model(value if value is not None else "unknown"))
    cvss_score = report.get("cvss_score")
    cvss_vector = report.get("cvss_vector")
    cvss = "Not assessed" if cvss_score is None and cvss_vector is None else (
        f"{clean(cvss_score)} ({clean(cvss_vector)})")
    lines = [
        f"# {clean(finding['title'])}", "",
        f"- Finding ID: `{finding_id}`",
        f"- Type: {clean(finding['type'])}",
        f"- Endpoint: `{clean(finding['endpoint'])}`",
        f"- Parameter: `{clean(finding['parameter'])}`",
        f"- CVSS: {cvss}", "",
        "## Impact", "", clean(finding["impact"]), "",
        "## Payloads / test inputs", ""]
    payloads = attacker.get("payloads", [])
    lines.extend(f"- `{clean(payload)}`" for payload in payloads) if payloads else lines.append("No standalone payload recorded.")
    lines.extend(["", "## Reproduction steps", ""])
    lines.extend(f"{index}. {clean(step)}" for index, step in enumerate(report["reproduction_steps"], 1))
    lines.extend(["", "## Reviewer checks", ""])
    lines.extend(f"- {clean(check)}" for check in report["false_positive_checks"])
    lines.extend(["", "## Evidence references", ""])
    lines.extend(f"- `{evidence_id}`" for evidence_id in report["evidence_refs"])
    evidence_by_id = {item["metadata"]["evidence_id"]: item for item in evidence}
    lines.extend(["", "## Evidence excerpts", ""])
    for evidence_id in report["evidence_refs"]:
        item = evidence_by_id[evidence_id]
        excerpt = clean(item.get("raw_content", ""))[:12000]
        excerpt = excerpt.replace("```", "`\u200b``")
        lines.extend([f"### `{evidence_id}` ({clean(item['metadata'].get('kind'))})", "",
                      "```text", excerpt, "```", ""])
    if report.get("limitations"):
        lines.extend(["## Limitations", ""])
        lines.extend(f"- {clean(item)}" for item in report["limitations"])
    return "\n".join(lines).rstrip() + "\n"
