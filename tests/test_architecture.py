"""Offline checks for the new workflow foundation; no network or LLM calls."""
import json
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hackmate.evidence import EvidenceRepository
from hackmate.orchestrator import Orchestrator, TaskStore
from hackmate.schema_validation import validate, SchemaValidationError
from hackmate.security import Scope, ScopeBoundEvalCDP, ScopeDenied, ScopeGate, request_method
from hackmate.tools import ToolContext, dispatch
from hackmate import tools as tools_module
from hackmate.cdp import CDPClient
from hackmate.agents import JsonRole, TokenBudget, redact_for_model, select_attack_adapter
from hackmate.agents.roles import (adapt_enumerate_site, validate_attacker_request,
                                  _reporter_xss_evidence_is_sufficient)
from hackmate.workflow import WorkflowService
from hackmate.research import ResearchRepository
from hackmate.webui import _ReconRedirectHandler, make_handler
from hackmate import eval as eval_module


class ArchitectureTests(unittest.TestCase):
    def test_cached_xss_status_cannot_confirm_a_new_task_without_raw_evidence(self):
        class CachedState:
            def tested_status(self, *_args):
                return "CONFIRMED"
        class Context:
            verify_state = CachedState()
            task_id = "task_new"
            evidence_repo = None
        result = json.loads(tools_module._h_verify_xss(
            {"url": "https://example.org/search?q=%3Cscript%3E"}, Context()))
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["evidence_refs"], [])
        self.assertTrue(result["cached"])

    def test_legacy_recon_redirects_are_checked_by_scope_gate(self):
        gate = ScopeGate(Scope("recon", ["https://example.org"], {"OBSERVE"}, paths=["/allowed"],
                               allow_private_network=True),
                         resolver=lambda *_args: [(None, None, None, None, ("93.184.216.34", 0))])
        handler = _ReconRedirectHandler(gate)
        request = Request("https://example.org/allowed/start")
        with self.assertRaises(ScopeDenied):
            handler.redirect_request(request, object(), 302, "Found", {},
                                     "https://outside.example/redirected")

    def test_recon_adapter_preserves_discovered_endpoints_and_input_locations(self):
        task = {"target": {"target_id": "t1", "base_url": "https://example.org/search?q=home",
                           "environment": "unknown"}}
        facts = {
            "url": "https://example.org/search?q=home", "url_params": ["q"],
            "links": ["/profile?id=7", "https://outside.example/path?token=x"],
            "api_endpoints": ["/api/v1/items?category=tools"],
            "forms": [{"action": "/search", "method": "post",
                       "fields": [{"name": "query", "type": "text"}]}],
            "inputs": [{"name": "loose-control", "type": "text"}],
        }
        recon = adapt_enumerate_site(task, json.dumps(facts), "ev_recon")
        by_url = {(item["url"], item["method"]): item for item in recon["endpoints"]}
        self.assertIn(("https://example.org/profile?id=7", "GET"), by_url)
        self.assertIn(("https://example.org/api/v1/items?category=tools", "GET"), by_url)
        form = by_url[("https://example.org/search", "POST")]
        self.assertIn({"name": "query", "location": "form"}, form["parameters"])
        self.assertIn({"name": "loose-control", "location": "unknown"},
                      by_url[("https://example.org/search?q=home", "GET")]["parameters"])
        self.assertFalse(any("outside.example" in item["url"] for item in recon["endpoints"]))
        self.assertTrue(all("ev_recon" in item["evidence_refs"] for item in recon["endpoints"]))

    def test_attacker_tools_must_be_named_in_the_analyze_plan(self):
        analysis = {"test_plan": [{"tool_capabilities": ["navigate"]}]}
        adapter, _ = select_attack_adapter({"hypotheses": [
            {"hypothesis_id": "h1", "type": "reflected_xss"}]}, "h1")
        self.assertTrue(validate_attacker_request(analysis, adapter, "navigate"))
        with self.assertRaisesRegex(ValueError, "not named in Analyze"):
            validate_attacker_request(analysis, adapter, "verify_xss")

    def test_reporter_requires_raw_request_response_and_execution_for_same_input(self):
        report = {"finding": {"type": "reflected_xss", "endpoint": "https://example.org/search",
                              "parameter": "q"},
                  "evidence_reviewed": ["req", "resp", "event"],
                  "evidence_refs": ["req", "resp", "event"]}
        attacker = {"hypothesis_id": "h1", "result": "CONFIRMED"}
        analysis = {"hypotheses": [{"hypothesis_id": "h1", "type": "reflected_xss"}]}
        evidence = [
            {"metadata": {"evidence_id": "req", "kind": "http_request"},
             "raw_content": json.dumps([{"method": "Network.requestWillBeSent", "params": {
                 "request": {"url": "https://example.org/search?q=one"}}}])},
            {"metadata": {"evidence_id": "resp", "kind": "http_response"},
             "raw_content": json.dumps([{"method": "Network.responseReceived", "params": {
                 "response": {"url": "https://example.org/search?q=one"}}}])},
            {"metadata": {"evidence_id": "event", "kind": "cdp_event"},
             "raw_content": json.dumps([{"method": "Page.javascriptDialogOpening", "params": {}}])},
        ]
        self.assertTrue(_reporter_xss_evidence_is_sufficient(report, attacker, analysis, evidence)[0])
        evidence[1]["raw_content"] = json.dumps([{"method": "Network.responseReceived", "params": {
            "response": {"url": "https://example.org/search?q=two"}}}])
        self.assertFalse(_reporter_xss_evidence_is_sufficient(report, attacker, analysis, evidence)[0])

    def test_evidence_repository_validates_and_returns_schema_conformant_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository = EvidenceRepository(tmp)
            item = repository.put("task_evidence", "http_response", "attacker", "raw response",
                                  content_type="text/plain", redaction_status="pending")
            schema = json.loads((BASE / "schemas/evidence.schema.json").read_text(encoding="utf-8"))
            validate(item, schema)
            self.assertTrue(item["captured_at"].endswith("+00:00"))
            with self.assertRaises(SchemaValidationError):
                repository.put("task_evidence", "unknown_kind", "attacker", "bad record")

    def test_skill_eval_browser_adapter_passes_gate_and_rechecks_read_target(self):
        class FakeCDP:
            def __init__(self):
                self.current_url = "https://example.org/eval"
                self.navigate_options = None
                self.verify_options = None
                self.reads = 0
            def navigate(self, url, **kwargs):
                self.navigate_options = kwargs
                self.current_url = url
                return "navigated"
            def verify_xss(self, url, **kwargs):
                self.verify_options = kwargs
                return '{"status":"INCONCLUSIVE"}'
            def ensure_test_tab(self):
                return {"url": self.current_url}
            def read_page_text(self, **_kwargs):
                self.reads += 1
                return "page text"

        resolver = lambda *_args: [(None, None, None, None, ("93.184.216.34", 0))]
        gate = ScopeGate(Scope("eval", ["https://example.org"], {"OBSERVE", "TEST"},
                               allow_private_network=True), resolver=resolver)
        raw = FakeCDP()
        cdp = ScopeBoundEvalCDP(raw, gate)
        cdp.navigate("https://example.org/eval")
        self.assertIs(raw.navigate_options["scope_gate"], gate)
        self.assertEqual(raw.navigate_options["action"], "TEST")
        cdp.verify_xss("https://example.org/eval?x=1")
        self.assertIs(raw.verify_options["scope_gate"], gate)
        raw.current_url = "https://outside.example/"
        with self.assertRaises(ScopeDenied):
            cdp.read_page_text()
        self.assertEqual(raw.reads, 0)
        raw.current_url = "https://example.org/eval"
        self.assertEqual(cdp.read_page_text(), "page text")
        self.assertEqual(raw.reads, 1)

    def test_skill_eval_rejects_out_of_scope_case_before_model_call(self):
        class FakeCDP:
            pass
        class FakeClient:
            calls = 0
            def ask(self, _prompt):
                self.calls += 1
                return "payload"

        gate = ScopeGate(Scope("eval", ["https://example.org"], {"OBSERVE", "TEST"},
                               allow_private_network=True),
                         resolver=lambda *_args: [(None, None, None, None, ("93.184.216.34", 0))])
        cdp = ScopeBoundEvalCDP(FakeCDP(), gate)
        producer = FakeClient()
        case = {"id": "outside", "context": "test", "reference_payload": "payload",
                "evidence": {"verify": "echo", "url": "https://outside.example/?q={payload}"}}
        with self.assertRaises(ScopeDenied):
            eval_module.score_group([case], "skill", producer, [], cdp, 1, "regression", vuln="sqli")
        self.assertEqual(producer.calls, 0)

    def test_scope_gate_requires_explicit_approval_and_checks_origin(self):
        with self.assertRaises(ScopeDenied):
            ScopeGate().check("OBSERVE", "https://example.org/")
        scope = Scope("s1", ["https://example.org"], {"OBSERVE", "TEST"}, allow_private_network=True)
        gate = ScopeGate(scope, resolver=lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))])
        self.assertEqual(gate.check("OBSERVE", "https://example.org/a")["decision"], "allow")
        with self.assertRaises(ScopeDenied):
            gate.check("TEST", "https://outside.example/")
        with self.assertRaises(ScopeDenied):
            gate.check("IMPACT", "https://example.org/")

    def test_scope_gate_checks_impact_operation_expiry_and_decoded_paths(self):
        resolver = lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))]
        scope = Scope("s2", ["https://example.org"], {"OBSERVE", "TEST", "IMPACT"},
                      paths=["/admin"], allow_private_network=True,
                      impact_approved=True, impact_actions={"click"})
        gate = ScopeGate(scope, resolver=resolver)
        self.assertEqual(gate.check("IMPACT", "https://example.org/admin", operation="click")["decision"], "allow")
        with self.assertRaises(ScopeDenied):
            gate.check("IMPACT", "https://example.org/admin", operation="race")
        with self.assertRaises(ScopeDenied):
            gate.check("OBSERVE", "https://example.org/admin/%252e%252e/public")
        with self.assertRaises(ScopeDenied):
            ScopeGate({"approved": True, "expires_at": "not-a-date", "origins": [], "actions": []})

    def test_scope_gate_detects_dns_answer_change(self):
        answers = ["93.184.216.34", "93.184.216.35"]
        calls = [0]
        def resolver(host, port):
            address = answers[min(calls[0], len(answers) - 1)]
            calls[0] += 1
            return [(None, None, None, None, (address, 0))]
        gate = ScopeGate(Scope("s4", ["https://example.org"], {"OBSERVE"}), resolver=resolver)
        gate.check("OBSERVE", "https://example.org/")
        with self.assertRaises(ScopeDenied):
            gate.check("OBSERVE", "https://example.org/next")

    def test_scope_gate_quota_and_dns_state_survive_reconstruction(self):
        resolver = lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))]
        scope = Scope("s_persist", ["https://example.org"], {"OBSERVE"},
                      max_requests=2, requests_per_minute=10)
        persisted = []
        gate = ScopeGate(scope, resolver=resolver, on_state_change=persisted.append)
        gate.check("OBSERVE", "https://example.org/")

        resumed = ScopeGate(scope, resolver=resolver, state=persisted[-1])
        resumed.check("OBSERVE", "https://example.org/next")
        with self.assertRaises(ScopeDenied):
            resumed.check("OBSERVE", "https://example.org/last")
        self.assertEqual(resumed.export_state()["total_requests"], 2)

    def test_total_quota_does_not_reset_when_rate_window_expires(self):
        resolver = lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))]
        scope = Scope("s_total", ["https://example.org"], {"OBSERVE"},
                      max_requests=1, requests_per_minute=1)
        old_state = {"total_requests": 1, "recent_requests": [],
                     "resolved_hosts": {"example.org": ["93.184.216.34"]}}
        resumed = ScopeGate(scope, resolver=resolver, state=old_state)
        with self.assertRaises(ScopeDenied):
            resumed.check("OBSERVE", "https://example.org/")

    def test_scope_validation_does_not_consume_request_quota(self):
        resolver = lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))]
        scope = Scope("s_validate", ["https://example.org"], {"OBSERVE"},
                      max_requests=1, requests_per_minute=1)
        gate = ScopeGate(scope, resolver=resolver)
        gate.check("OBSERVE", "https://example.org/", count=0)
        self.assertEqual(gate.export_state()["total_requests"], 0)
        gate.check("OBSERVE", "https://example.org/")
        with self.assertRaises(ScopeDenied):
            gate.check("OBSERVE", "https://example.org/")

    def test_scope_gate_state_is_persisted_in_task_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "tasks.sqlite3"
            store = TaskStore(database)
            task = store.create({"base_url": "https://example.org/"}, {"approved": True})
            state = {"total_requests": 3, "recent_requests": [1.0, 2.0],
                     "resolved_hosts": {"example.org": ["93.184.216.34"]}}
            store.save_gate_state(task["task_id"], state)
            reopened = TaskStore(database)
            self.assertEqual(reopened.get_gate_state(task["task_id"]), state)

    def test_mutating_http_method_requires_explicit_impact_operation(self):
        resolver = lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))]
        test_only = ScopeGate(Scope("s5", ["https://example.org"], {"TEST"},
                                    methods={"POST"}, allow_private_network=True), resolver=resolver)
        with self.assertRaises(ScopeDenied):
            test_only.check("TEST", "https://example.org/form", method="POST", operation="fill_form")
        approved = ScopeGate(Scope("s6", ["https://example.org"], {"TEST", "IMPACT"},
                                   methods={"POST"}, allow_private_network=True,
                                   impact_approved=True, impact_actions={"fill_form"}), resolver=resolver)
        self.assertEqual(approved.check("TEST", "https://example.org/form", method="POST",
                                        operation="fill_form")["action"], "IMPACT")

    def test_dispatch_denies_before_handler_without_scope(self):
        ctx = ToolContext({}, None, None, lambda: None)
        result = json.loads(dispatch("navigate", {"url": "https://example.org/"}, ctx))
        self.assertEqual(result["status"], "BLOCKED")
        ctx.scope_gate = None
        no_gate = json.loads(dispatch("navigate", {"url": "https://example.org/"}, ctx))
        self.assertEqual(no_gate["status"], "BLOCKED")
        entry = {"name": "mcp_unknown_exec", "handler": lambda *_: "executed", "parameters": {}, "description": "test"}
        tools_module.REGISTRY.append(entry)
        tools_module._BY_NAME[entry["name"]] = entry
        try:
            unknown = json.loads(dispatch("mcp_unknown_exec", {}, ctx))
            self.assertEqual(unknown["status"], "BLOCKED")
        finally:
            tools_module.REGISTRY.remove(entry)
            tools_module._BY_NAME.pop(entry["name"], None)

    def test_generic_vendor_cli_is_blocked_until_redirect_safe_adapter_exists(self):
        scope = Scope("s3", ["https://example.org"], {"TEST"}, allow_private_network=True)
        ctx = ToolContext({}, None, None, lambda: None, scope_gate=ScopeGate(
            scope, resolver=lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))]))
        result = json.loads(dispatch("run_tool", {"tool": "sqlmap", "args": "-u https://example.org/"}, ctx))
        self.assertEqual(result["status"], "BLOCKED")

    def test_ambiguous_shell_and_raw_request_methods_fail_closed(self):
        with self.assertRaises(ScopeDenied):
            request_method("run_shell", {"command": "curl https://example.org/"})
        with self.assertRaises(ScopeDenied):
            request_method("run_tool", {"args": "-r request.txt"})
        self.assertEqual(request_method("run_tool", {"args": "-u https://example.org/ --data x=1"}), "POST")

    def test_browser_redirect_request_is_intercepted_by_scope_gate(self):
        class FakeSocket:
            sent = None
            def send(self, value):
                self.sent = json.loads(value)
        gate = ScopeGate(Scope("s1", ["https://example.org"], {"OBSERVE"}, allow_private_network=True),
                         resolver=lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))])
        ws = FakeSocket()
        CDPClient._scope_event(ws, {"method": "Fetch.requestPaused", "params": {
            "requestId": "r1", "request": {"url": "https://outside.example/", "method": "GET"}}},
            gate, "OBSERVE", lambda: 17)
        self.assertEqual(ws.sent["method"], "Fetch.failRequest")

    def test_evidence_round_trip_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = EvidenceRepository(tmp)
            item = repo.put("task_a", "tool_output", "attacker", "raw evidence")
            self.assertEqual(repo.read(item["evidence_id"]), b"raw evidence")
            self.assertEqual(repo.list_task("task_a")[0]["sha256"], item["sha256"])

    def test_research_candidate_requires_validation_eval_approval_and_skill_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = EvidenceRepository(Path(tmp) / "evidence")
            research = ResearchRepository(Path(tmp) / "research.sqlite3", evidence)
            source = research.capture_source(
                "task_a", "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
                "NVD advisory", "A component issue affects versions before 2.0.")
            candidate = research.create(
                "task_a", "wordpress_component_cve", "Component version check",
                "The observed version range is affected.",
                "Check the installed component version against the advisory range.",
                [source["evidence_id"]], ["Identify the exact component version.", "Compare it with the advisory."])
            with self.assertRaises(ValueError):
                research.record_validation(candidate["candidate_id"], [source["evidence_id"]], True,
                                           "The advisory was read, but the target was not validated.")
            with self.assertRaises(TypeError):
                research.record_eval(candidate["candidate_id"], "true", "invalid type")
            with self.assertRaises(ValueError):
                research.approve(candidate["candidate_id"], "user")
            validation = evidence.put("task_a", "http_response", "attacker", "Observed version: 1.4")
            candidate = research.record_validation(
                candidate["candidate_id"], [validation["evidence_id"]], True,
                "The local fixture reports version 1.4.")
            candidate = research.record_eval(candidate["candidate_id"], True,
                                             "All research candidate regression cases passed.", {
                                                 "skill_ref": "skills/wordpress/components.md",
                                                 "before": {"regression": 0.5, "hidden": 0.5},
                                                 "candidate": {"regression": 0.6, "hidden": 0.6}})
            with self.assertRaises(ValueError):
                research.promote(candidate["candidate_id"], lambda _candidate: {"kept": True, "skill_ref": "x"})
            candidate = research.approve(candidate["candidate_id"], "user")
            missing_eval = research.promote(candidate["candidate_id"], lambda _candidate: {
                "kept": True, "skill_ref": "skills/wordpress/components.md"})
            self.assertFalse(missing_eval["promoted"])
            skill_eval = research.capture_skill_eval(
                candidate["candidate_id"], True, "skills/wordpress/components.md",
                "Before/after regression and hidden Eval passed.")
            outcome = research.promote(candidate["candidate_id"], lambda approved: {
                "kept": approved["status"] == "approved", "skill_ref": "skills/wordpress/components.md",
                "skill_eval_ref": skill_eval["evidence_id"]})
            self.assertTrue(outcome["promoted"])
            self.assertEqual(outcome["candidate"]["status"], "promoted")
            transitions = [event["to_status"] for event in research.timeline(candidate["candidate_id"])
                           if event["from_status"] != event["to_status"]]
            self.assertEqual(transitions, ["proposed", "validated", "eval_passed", "approved", "promoted"])

    def test_research_candidate_cannot_use_cross_task_source_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = EvidenceRepository(Path(tmp) / "evidence")
            research = ResearchRepository(Path(tmp) / "research.sqlite3", evidence)
            source = research.capture_source("task_a", "https://example.org/advisory", "source", "details")
            with self.assertRaises(ValueError):
                research.create("task_b", "sqli", "SQL issue", "claim", "knowledge",
                                [source["evidence_id"]], ["validate"])

    def test_task_scoped_nvd_search_is_saved_as_research_source_evidence(self):
        class FakeResponse:
            headers = {"Content-Type": "application/json"}
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self):
                return json.dumps({"vulnerabilities": [{"cve": {
                    "id": "CVE-2026-12345",
                    "descriptions": [{"value": "A test component issue."}]}}]}).encode()
        class FakeOpener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return FakeResponse()
        with tempfile.TemporaryDirectory() as tmp:
            evidence = EvidenceRepository(Path(tmp) / "evidence")
            scope = Scope("nvd", [], {"OBSERVE"})
            ctx = ToolContext({}, None, None, lambda: None,
                              scope_gate=ScopeGate(scope), evidence_repo=evidence, task_id="task_nvd")
            with patch("urllib.request.build_opener", return_value=FakeOpener()):
                output = dispatch("search_cve", {"keyword": "test component"}, ctx)
            self.assertIn("CVE-2026-12345", output)
            refs = [item for item in evidence.list_task("task_nvd") if item["kind"] == "research_source"]
            self.assertEqual(len(refs), 1)
            self.assertIn("services.nvd.nist.gov", refs[0]["metadata"]["url"])

    def test_research_search_and_candidate_creation_use_finished_task_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = WorkflowService(
                {}, object(), None, lambda: None, Path(tmp) / "workflow")
            task = service.create_task(
                {"target_id": "target_a", "base_url": "https://example.org/"},
                {"scope_id": "scope_a", "revision": 1, "approved": True,
                 "origins": ["https://example.org"], "actions": ["OBSERVE"],
                 "approval_source": "offline fixture", "allow_private_network": True})
            with self.assertRaises(ValueError):
                service.search_research(task["task_id"], "Example Plugin")
            service.store.transition(task["task_id"], "VALIDATING_SCOPE", "fixture")
            service.store.transition(task["task_id"], "BLOCKED", "fixture", actor="scope_gate")

            def fake_dispatch(name, args, ctx):
                self.assertEqual(name, "search_cve")
                self.assertEqual(ctx.task_id, task["task_id"])
                ctx.scope_gate.check("OBSERVE", count=1, operation=name)
                source = ctx.evidence_repo.put(
                    ctx.task_id, "research_source", "research", "NVD fixture",
                    content_type="application/json", metadata={
                        "url": "https://nvd.nist.gov/example", "title": f"NVD CVE keyword search: {args['keyword']}"})
                return "NVD fixture result"

            with patch("hackmate.tools.dispatch", side_effect=fake_dispatch):
                search = service.search_research(task["task_id"], "Example Plugin")
            self.assertEqual(search["result"], "NVD fixture result")
            self.assertEqual(len(search["source_refs"]), 1)
            self.assertEqual(service.store.get_gate_state(task["task_id"])["total_requests"], 1)
            candidate = service.create_research_candidate(task["task_id"], {
                "vulnerability_type": "wordpress_component_cve",
                "title": "Example plugin version check", "claim": "Version 1.0 is affected",
                "proposed_knowledge": "Compare the installed version with the advisory range.",
                "source_refs": search["source_refs"],
                "validation_plan": ["Confirm the installed component version in the authorized target."]})
            snapshot = service.research_snapshot(task["task_id"])
            self.assertEqual(snapshot["candidates"][0]["candidate_id"], candidate["candidate_id"])
            self.assertEqual(snapshot["sources"][0]["evidence_id"], search["source_refs"][0])

    def test_research_candidate_eval_uses_existing_regression_and_hidden_sets(self):
        class FakeClient:
            def clone(self, **_kwargs):
                return object()

        with tempfile.TemporaryDirectory() as tmp:
            service = WorkflowService({"model": "fake"}, FakeClient(), None, lambda: None,
                                      Path(tmp) / "workflow")
            task = service.create_task(
                {"target_id": "target_eval", "base_url": "https://example.org/"},
                {"scope_id": "scope_eval", "revision": 1, "approved": True,
                 "origins": ["https://example.org"], "actions": ["OBSERVE", "TEST"],
                 "approval_source": "offline fixture", "allow_private_network": True})
            service.store.transition(task["task_id"], "VALIDATING_SCOPE", "fixture")
            service.store.transition(task["task_id"], "BLOCKED", "fixture", actor="scope_gate")
            source = service.evidence.put(task["task_id"], "research_source", "research", "source")
            candidate = service.create_research_candidate(task["task_id"], {
                "vulnerability_type": "reflected_xss", "title": "Context rule",
                "claim": "The candidate rule generalizes", "proposed_knowledge": "Use context-aware encoding signals.",
                "source_refs": [source["evidence_id"]], "validation_plan": ["Check the authorized fixture."]})
            response = service.evidence.put(task["task_id"], "http_response", "attacker", "fixture response")
            service.record_research_validation(task["task_id"], candidate["candidate_id"],
                                               [response["evidence_id"]], True, "Verified in the local fixture.")
            score_calls = []
            def fake_score(_cases, content, *_args, **_kwargs):
                score_calls.append(content)
                value = 0.7 if "Research candidate for Eval" in content else 0.5
                return value, []
            with patch("hackmate.eval.sample_round", return_value=[{"id": "reg1"}]), \
                    patch("hackmate.eval.sample_hidden_round", return_value=[{"id": "hid1"}]), \
                    patch("hackmate.eval.score_group", side_effect=fake_score):
                evaluated = service.evaluate_research_candidate(
                    task["task_id"], candidate["candidate_id"], "xss", "reflection_xss")
            self.assertEqual(evaluated["status"], "eval_passed")
            self.assertEqual(len(score_calls), 4)
            artifact = json.loads(service.evidence.read(evaluated["eval_ref"]).decode("utf-8"))
            self.assertEqual(artifact["details"]["skill_ref"], "skills/xss/reflection_xss.md")
            self.assertEqual(artifact["details"]["regression_cases"], 1)
            self.assertEqual(artifact["details"]["hidden_cases"], 1)

    def test_research_promotion_uses_skill_gate_and_requires_impact_scope(self):
        class FakeJob:
            id = 71
            status = "queued"
            def check_cancel(self):
                return None
            def set_progress(self, _value):
                return None
        class ImmediateJobs:
            def submit(self, _kind, fn, title=""):
                job = FakeJob()
                job.title = title
                job.status = "running"
                job.result = fn(job)
                job.status = "done"
                return job

        with tempfile.TemporaryDirectory() as tmp:
            service = WorkflowService({}, object(), ImmediateJobs(), lambda: None, Path(tmp) / "workflow")
            task = service.create_task(
                {"target_id": "target_promote", "base_url": "https://example.org/"},
                {"scope_id": "scope_promote", "revision": 1, "approved": True,
                 "origins": ["https://example.org"], "actions": ["OBSERVE", "IMPACT"],
                 "approval_source": "offline fixture", "allow_private_network": True,
                 "impact_approved": True, "impact_actions": ["improve_skill"], "max_requests": 5})
            service.store.transition(task["task_id"], "VALIDATING_SCOPE", "fixture")
            service.store.transition(task["task_id"], "BLOCKED", "fixture", actor="scope_gate")
            source = service.evidence.put(task["task_id"], "research_source", "research", "source")
            candidate = service.create_research_candidate(task["task_id"], {
                "vulnerability_type": "reflected_xss", "title": "Context rule",
                "claim": "The candidate rule generalizes", "proposed_knowledge": "Use context-aware encoding signals.",
                "source_refs": [source["evidence_id"]], "validation_plan": ["Check the authorized fixture."]})
            response = service.evidence.put(task["task_id"], "http_response", "attacker", "fixture response")
            candidate = service.record_research_validation(
                task["task_id"], candidate["candidate_id"], [response["evidence_id"]], True,
                "Verified in the local fixture.")
            candidate = service.research.record_eval(candidate["candidate_id"], True, "Eval passed", {
                "skill_ref": "skills/xss/reflection_xss.md",
                "before": {"regression": 0.5, "hidden": 0.5},
                "candidate": {"regression": 0.6, "hidden": 0.6}})
            service.approve_research_candidate(task["task_id"], candidate["candidate_id"], "reviewer")
            with patch("hackmate.skill.run_improvement", return_value={
                    "kept": True, "skill_ref": "skills/xss/reflection_xss.md",
                    "summary": "regression and hidden Eval passed"}) as run_improvement:
                submitted = service.submit_research_promotion(
                    task["task_id"], candidate["candidate_id"], "xss", "reflection_xss")
            self.assertEqual(submitted["job_id"], 71)
            self.assertEqual(service.research.get(candidate["candidate_id"])["status"], "promoted")
            self.assertEqual(service.store.get_gate_state(task["task_id"])["total_requests"], 1)
            self.assertEqual(run_improvement.call_args.kwargs["research_knowledge"],
                             "Use context-aware encoding signals.")
            self.assertTrue(run_improvement.call_args.kwargs["strict_eval"])

    def test_local_web_research_endpoints_return_search_and_candidate_results(self):
        class FakeSession:
            def research_search(self, task_id, keyword):
                return {"task_id": task_id, "keyword": keyword,
                        "result": "NVD result", "source_refs": ["ev_source"]}
            def create_research_candidate(self, task_id, candidate):
                return {"task_id": task_id, **candidate, "candidate_id": "research_fixture"}
            def research_snapshot(self, task_id):
                return {"task_id": task_id, "sources": [], "candidates": []}
            def validate_research_candidate(self, task_id, payload):
                return {"task_id": task_id, "candidate_id": payload["candidate_id"], "status": "validated"}
            def evaluate_research_candidate(self, task_id, payload):
                return {"task_id": task_id, "job_id": 72, "status": "queued"}
            def approve_research_candidate(self, task_id, candidate_id):
                return {"task_id": task_id, "candidate_id": candidate_id, "status": "approved"}
            def promote_research_candidate(self, task_id, payload):
                return {"task_id": task_id, "job_id": 73, "status": "queued"}

        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(FakeSession(), port))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{port}/api/research/task_fixture") as response:
                snapshot = json.loads(response.read().decode("utf-8"))
            self.assertEqual(snapshot["task_id"], "task_fixture")
            request = Request(
                f"http://127.0.0.1:{port}/api/research/search",
                data=json.dumps({"task_id": "task_fixture", "keyword": "Example Plugin"}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request) as response:
                search = json.loads(response.read().decode("utf-8"))
            self.assertEqual(search["source_refs"], ["ev_source"])
            candidate = {"vulnerability_type": "wordpress_component_cve", "source_refs": ["ev_source"]}
            request = Request(
                f"http://127.0.0.1:{port}/api/research/candidate",
                data=json.dumps({"task_id": "task_fixture", "candidate": candidate}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request) as response:
                created = json.loads(response.read().decode("utf-8"))
            self.assertEqual(created["candidate"]["candidate_id"], "research_fixture")
            api_steps = [
                ("/api/research/validation", {"candidate_id": "research_fixture", "passed": True,
                                              "evidence_refs": ["ev_response"], "notes": "observed"}, 200),
                ("/api/research/evaluate", {"candidate_id": "research_fixture", "vuln": "xss",
                                            "variant": "reflection_xss"}, 202),
                ("/api/research/approve", {"candidate_id": "research_fixture"}, 200),
                ("/api/research/promote", {"candidate_id": "research_fixture", "vuln": "xss",
                                            "variant": "reflection_xss"}, 202),
            ]
            for path, fields, expected_status in api_steps:
                request = Request(
                    f"http://127.0.0.1:{port}{path}",
                    data=json.dumps({"task_id": "task_fixture", **fields}).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
                with urlopen(request) as response:
                    self.assertEqual(response.status, expected_status)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_model_prompt_copy_redacts_credentials_without_mutating_source(self):
        raw = {
            "headers": "Authorization: Bearer abc.def\nCookie: sid=secret-cookie",
            "access_token": "json-token",
            "body": '<input name="csrf_token" value="html-token">',
            "url": "https://example.org/?token=query-token&x=1",
            "network_event": '{"request":{"headers":{"Cookie":"sid=json-cookie","Authorization":"Basic basic-token"}}}',
        }
        sanitized = redact_for_model(raw)
        rendered = json.dumps(sanitized)
        for secret in ("abc.def", "secret-cookie", "json-token", "html-token", "query-token",
                       "json-cookie", "basic-token"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(raw["access_token"], "json-token")

    def test_json_role_sanitizes_prompt_and_validates_role_output(self):
        class FakeClient:
            prompt = ""
            def clone(self, **_kwargs):
                return self
            def ask(self, prompt):
                self.prompt = prompt
                return json.dumps({
                    "target": {"target_id": "t1", "base_url": "https://example.org/", "environment": "unknown"},
                    "technologies": [], "infrastructure": [], "endpoints": [],
                    "authentication": "unknown", "observations": [], "evidence_refs": [], "limitations": [],
                })
        client = FakeClient()
        result = JsonRole(client, "recon", max_retries=0).ask({"headers": "Cookie: session=private-value"})
        self.assertEqual(result["authentication"], "unknown")
        self.assertNotIn("private-value", client.prompt)

    def test_json_role_retries_transient_model_errors_within_retry_budget(self):
        class RetryableError(Exception):
            retryable = True
        class FakeClient:
            calls = 0
            max_retries = 2
            retry_limits = []
            def clone(self, **_kwargs):
                return self
            def ask(self, _prompt):
                self.calls += 1
                self.retry_limits.append(self.max_retries)
                if self.calls == 1:
                    raise RetryableError("temporary connection failure")
                return json.dumps({
                    "target": {"target_id": "t1", "base_url": "https://example.org/", "environment": "unknown"},
                    "technologies": [], "infrastructure": [], "endpoints": [],
                    "authentication": "unknown", "observations": [], "evidence_refs": [], "limitations": [],
                })
        client = FakeClient()
        result = JsonRole(client, "recon", max_retries=1).ask({"target": "https://example.org/"})
        self.assertEqual(result["target"]["target_id"], "t1")
        self.assertEqual(client.calls, 2)
        self.assertEqual(client.retry_limits, [0, 0])

    def test_attack_adapter_is_extensible_but_only_xss_is_enabled(self):
        analysis = {"hypotheses": [
            {"hypothesis_id": "h-xss", "type": "reflected_xss"},
            {"hypothesis_id": "h-sqli", "type": "sqli"},
        ]}
        xss, reason = select_attack_adapter(analysis, "h-xss")
        self.assertEqual(xss["tools"], {"navigate", "read_page_text", "read_element", "find_xss_entries", "verify_xss"})
        self.assertEqual(reason, "")
        sqli, reason = select_attack_adapter(analysis, "h-sqli")
        self.assertIsNone(sqli)
        self.assertIn("暂无 Attacker 执行适配器", reason)

    def test_state_machine_mandates_reporter_and_persists_transitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.sqlite3")
            task = store.create({"base_url": "https://example.org/"}, {"approved": True})
            orch = Orchestrator(store, {
                "recon": lambda *_: {"facts": []},
                "analyze": lambda *_: {"plan": []},
                "attacker": lambda *_: {"result": "INCONCLUSIVE"},
                "reporter": lambda *_: {"verdict": "needs_more_evidence"},
            }, lambda *_: True)
            result = orch.run(task["task_id"])
            self.assertEqual(result["status"], "COMPLETED")
            self.assertIn("reporter", result["results"])
            commander = result["results"]["commander"]
            self.assertEqual(commander["agent"], "commander")
            self.assertEqual(commander["task_id"], task["task_id"])
            with self.assertRaises(ValueError):
                store.transition(task["task_id"], "ATTACK_RUNNING", "skip review")

    def test_contract_validator_rejects_missing_fields(self):
        schema = json.loads((Path(__file__).resolve().parent.parent / "schemas" / "recon_result.schema.json").read_text(encoding="utf-8"))
        with self.assertRaises(SchemaValidationError):
            validate({"target": {}}, schema)
        with self.assertRaises(SchemaValidationError):
            validate("2026-11-02T10:00:00", {"type": "string", "format": "date-time"})
        reporter_schema = json.loads((Path(__file__).resolve().parent.parent / "schemas" / "reporter_result.schema.json").read_text(encoding="utf-8"))
        validate({"verdict": "needs_more_evidence", "evidence_reviewed": [],
                  "reproducibility": "not_assessed", "impact_assessment": "unknown",
                  "finding": None, "reproduction_steps": [], "false_positive_checks": [],
                  "evidence_refs": [], "writeup_ref": None, "finding_ref": None,
                  "limitations": ["no evidence"]}, reporter_schema)

    def test_recovery_resumes_at_reporter_without_replaying_attacker(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.sqlite3")
            task = store.create({"base_url": "https://example.org/"}, {"approved": True})
            store.transition(task["task_id"], "VALIDATING_SCOPE", "test")
            store.transition(task["task_id"], "RECON_RUNNING", "test")
            store.save_result(task["task_id"], "recon", {"facts": []})
            store.transition(task["task_id"], "ANALYZE_RUNNING", "test")
            store.save_result(task["task_id"], "analyze", {"plan": []})
            store.transition(task["task_id"], "ATTACK_RUNNING", "test")
            store.save_result(task["task_id"], "attacker", {"result": "INCONCLUSIVE"})
            store.transition(task["task_id"], "REPORT_RUNNING", "test")
            store.recover(task["task_id"])
            calls = []
            orch = Orchestrator(store, {"reporter": lambda *_: calls.append("reporter") or {
                "verdict": "needs_more_evidence", "evidence_reviewed": [], "evidence_refs": []}},
                lambda *_: True)
            result = orch.resume(task["task_id"])
            self.assertEqual(result["status"], "COMPLETED")
            self.assertEqual(calls, ["reporter"])
            self.assertEqual(result["results"]["attacker"]["result"], "INCONCLUSIVE")

    def test_recovery_refuses_to_replay_interrupted_attack(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.sqlite3")
            task = store.create({"base_url": "https://example.org/"}, {"approved": True})
            store.transition(task["task_id"], "VALIDATING_SCOPE", "test")
            store.transition(task["task_id"], "RECON_RUNNING", "test")
            store.save_result(task["task_id"], "recon", {"facts": []})
            store.transition(task["task_id"], "ANALYZE_RUNNING", "test")
            store.save_result(task["task_id"], "analyze", {"plan": []})
            store.transition(task["task_id"], "ATTACK_RUNNING", "test")
            store.recover(task["task_id"])
            with self.assertRaises(RuntimeError):
                store.prepare_resume(task["task_id"])

    def test_cancellation_persists_commander_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.sqlite3")
            task = store.create({"base_url": "https://example.org/"}, {"approved": True})
            orch = Orchestrator(store, {"recon": lambda *_: (_ for _ in ()).throw(RuntimeError("cancelled"))},
                                lambda *_: True)
            result = orch.run(task["task_id"], cancel_check=lambda: True)
            self.assertEqual(result["status"], "CANCELLED")
            self.assertEqual(result["results"]["commander"]["status"], "CANCELLED")

    def test_task_contract_and_token_budget_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = WorkflowService({}, None, None, lambda: None, Path(tmp) / "workflow")
            target = {"target_id": "t1", "base_url": "https://example.org/", "environment": "unknown"}
            scope = {"scope_id": "s1", "revision": 1, "approved": True,
                     "origins": ["https://example.org"], "path_prefixes": ["/"],
                     "methods": ["GET"], "actions": ["OBSERVE", "TEST"],
                     "approval_source": "user"}
            task = service.create_task(target, scope)
            self.assertEqual(task["budget"]["max_tokens"], 24000)
            self.assertTrue(task["created_at"].endswith("+00:00"))
        budget = TokenBudget(max_tokens=100)
        with self.assertRaises(RuntimeError):
            budget.before("x" * 1000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
