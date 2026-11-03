"""Offline integration acceptance tests corresponding to evals/workflow/integration.json."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hackmate.orchestrator import Orchestrator, TaskStore
from hackmate.workflow import WorkflowService


class WorkflowEvalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((BASE / "evals/workflow/integration.json").read_text(encoding="utf-8"))
        cls.cases = {case["id"]: case for case in cls.fixture["cases"]}

    def make_store(self, tmp):
        store = TaskStore(Path(tmp) / "tasks.sqlite3")
        task = store.create({"base_url": "https://example.org/"}, {"approved": True})
        return store, task

    def test_scope_denial_stops_before_any_agent(self):
        case = self.cases["scope-deny-stops-before-recon"]
        with tempfile.TemporaryDirectory() as tmp:
            store, task = self.make_store(tmp)
            calls = []
            agents = {name: lambda *_args, n=name: calls.append(n) or {} for name in ("recon", "analyze", "attacker", "reporter")}
            result = Orchestrator(store, agents, lambda *_: (_ for _ in ()).throw(PermissionError("denied"))).run(task["task_id"])
            self.assertEqual(result["status"], case["expected_status"])
            self.assertEqual(calls, case["expected_stages"])

    def test_real_role_wiring_runs_offline_with_fake_model_and_browser(self):
        case = self.cases["role-adapters-run-offline-through-commander"]

        class FakeCDP:
            verify_calls = []
            def enumerate_site(self, url, index=0, test_tab=False, scope_gate=None):
                scope_gate.check("OBSERVE", url, "GET", operation="enumerate_site")
                return json.dumps({"url": url, "parameters": ["q"]})

            def navigate(self, url, index=0, test_tab=False, scope_gate=None, action="OBSERVE"):
                scope_gate.check(action, url, "GET", operation="navigate")
                return "fake browser navigation completed"

            def verify_xss(self, url, index=0, wait=4, autotrigger=True,
                           test_tab=False, scope_gate=None):
                self.verify_calls.append(url)
                scope_gate.check("TEST", url, "GET", operation="verify_xss")
                baseline = "test123" in url
                network_events = [
                    {"method": "Network.requestWillBeSent", "params": {
                        "request": {"url": url, "method": "GET"}}},
                    {"method": "Network.responseReceived", "params": {
                        "response": {"url": url, "status": 200}}},
                ]
                return json.dumps({
                    "status": "NOT_CONFIRMED" if baseline else "CONFIRMED",
                    "network_events": network_events,
                    "browser_events": [] if baseline else [{
                        "method": "Page.javascriptDialogOpening",
                        "params": {"message": "xss-fixture"}}],
                    "response_bodies": [{"url": url, "status": 200,
                                         "body": "baseline" if baseline else "<script>"}],
                    "evidence": "offline CDP fixture",
                })

        class FakeRoleClient:
            def __init__(self, role=""):
                self.role = role
                self.last_usage = None
            def clone(self, system_prompt="", **_kwargs):
                prompt_lower = system_prompt.lower()
                if "collect facts only" in prompt_lower:
                    role = "recon"
                elif "analyze supplied reconnaissance" in prompt_lower:
                    role = "analyze"
                elif "execute only the supplied plan" in prompt_lower:
                    role = "attacker"
                elif "independently review the raw evidence" in prompt_lower:
                    role = "reporter"
                else:
                    role = ""
                return FakeRoleClient(role)
            def ask(self, prompt):
                raw = prompt.split("INPUT:", 1)[1].split("\nREPAIR FEEDBACK:", 1)[0]
                inputs = json.loads(raw)
                task = inputs["task"]
                if self.role == "recon":
                    facts = inputs["recon_facts"]
                    result = {"target": task["target"], "technologies": [], "infrastructure": [],
                              "endpoints": facts["endpoints"], "authentication": "unknown",
                              "observations": facts["observations"],
                              "evidence_refs": facts["evidence_refs"], "limitations": facts["limitations"]}
                elif self.role == "analyze":
                    recon = inputs["recon"]
                    result = {"attack_surface": [task["target"]["base_url"]],
                              "input_point": {"endpoint": task["target"]["base_url"],
                                              "parameter": "q", "location": "query"},
                              "hypotheses": [{"hypothesis_id": "h1", "type": "reflected_xss",
                                              "reasoning": "offline fixture", "priority": "high",
                                              "evidence_refs": recon["evidence_refs"]}],
                              "test_plan": [{"step_id": "step1", "test_type": "reflection_check",
                                             "objective": "check the input point",
                                             "tool_capabilities": ["verify_xss"],
                                             "expected_evidence": ["response observation"], "constraints": []}],
                              "limitations": []}
                elif self.role == "attacker":
                    if inputs["prior_attempts"]:
                        result = {"hypothesis_id": "h1", "tool_request": None, "payloads": [],
                                  "decision": "stop", "reason": "offline evidence is inconclusive",
                                  "limitations": []}
                    else:
                        test_url = task["target"]["base_url"] + "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
                        result = {"hypothesis_id": "h1", "tool_request": {"tool": "verify_xss",
                                  "args": {"url": test_url}}, "payloads": ["<script>alert(1)</script>"],
                                  "decision": "continue", "reason": "open the planned page",
                                  "limitations": []}
                else:
                    attacker = inputs["attacker_result"]
                    refs = attacker["evidence_refs"]
                    if task["user_request"] == "accept":
                        result = {"verdict": "accepted", "finding": {
                                      "type": "reflected_xss", "title": "Reflected XSS",
                                      "endpoint": task["target"]["base_url"], "parameter": "q",
                                      "impact": "Script executes in the target origin."},
                                  "reproduction_steps": ["Open the recorded URL in the test browser."],
                                  "false_positive_checks": ["Confirmed the request targets the application origin."],
                                  "evidence_reviewed": refs, "reproducibility": "reproducible",
                                  "impact_assessment": "Script executes in the target origin.",
                                  "evidence_refs": refs, "writeup_ref": None, "finding_ref": None,
                                  "limitations": ["offline adapter fixture"]}
                    else:
                        result = {"verdict": "needs_more_evidence", "finding": None,
                                  "reproduction_steps": [], "false_positive_checks": [],
                                  "evidence_reviewed": refs, "reproducibility": "not_assessed",
                                  "impact_assessment": "not assessed", "evidence_refs": [],
                                  "writeup_ref": None, "finding_ref": None,
                                  "limitations": ["offline adapter fixture"]}
                return json.dumps(result)

        with tempfile.TemporaryDirectory() as tmp:
            target = {"target_id": "t_offline", "base_url": "http://127.0.0.1:8080/",
                      "environment": "local_lab"}
            scope = {"scope_id": "offline", "revision": 1, "approved": True,
                     "origins": ["http://127.0.0.1:8080"], "path_prefixes": ["/"],
                     "methods": ["GET"], "actions": ["OBSERVE", "TEST"],
                     "approval_source": "test", "allow_private_network": True,
                     "max_requests": 30}
            service = WorkflowService({}, FakeRoleClient(), None, lambda: FakeCDP(), Path(tmp) / "workflow")
            task = service.create_task(target, scope)
            result = service.run_task(task["task_id"])
            self.assertEqual(result["status"], case["expected_status"], service.get_task(task["task_id"]))
            saved = service.get_task(task["task_id"])
            task_schema = json.loads((BASE / "schemas/task.schema.json").read_text(encoding="utf-8"))
            from hackmate.schema_validation import validate
            validate(saved, task_schema)
            self.assertEqual(set(saved["results"]), set(case["expected_stages"]))
            self.assertEqual(saved["results"]["commander"]["reporter_verdict"], "needs_more_evidence")
            self.assertEqual(saved["workflow_retry_count"], 1)
            self.assertEqual(len(saved["results_history"]["analyze"]), 2)
            attacker_result = saved["results"]["attacker"]
            self.assertEqual(len(attacker_result["attempts"]), 1)
            self.assertTrue(attacker_result["execution_refs"][0].startswith("ev_"))
            execution_artifact = json.loads(service.evidence.read(attacker_result["execution_refs"][0]).decode("utf-8"))
            execution_schema = json.loads((BASE / "schemas/execution.schema.json").read_text(encoding="utf-8"))
            validate(execution_artifact, execution_schema)

            quota_case = self.cases["request-quota-is-shared-across-stages"]
            limited_scope = dict(scope)
            limited_scope["scope_id"] = "offline-limited"
            limited_scope["max_requests"] = 3
            limited_task = service.create_task(target, limited_scope)
            limited_result = service.run_task(limited_task["task_id"])
            limited_saved = service.get_task(limited_task["task_id"])
            self.assertEqual(limited_result["status"], quota_case["expected_status"])
            self.assertEqual(set(limited_saved["results"]), set(quota_case["expected_stages"]))
            self.assertEqual(limited_saved["scope_gate_state"]["total_requests"], 3)
            self.assertEqual(limited_saved["results"]["attacker"]["result"], "BLOCKED")

            report_case = self.cases["reporter-generates-reviewed-writeup"]
            accepted_task = service.create_task(target, scope, user_request="accept")
            accepted_result = service.run_task(accepted_task["task_id"])
            accepted_saved = service.get_task(accepted_task["task_id"])
            report = accepted_saved["results"]["reporter"]
            self.assertEqual(accepted_result["status"], report_case["expected_status"])
            self.assertEqual(report["verdict"], "accepted", accepted_saved["results_history"]["reporter"])
            self.assertTrue(report["writeup_ref"].startswith("ev_"))
            writeup = service.evidence.read(report["writeup_ref"]).decode("utf-8")
            self.assertIn("## Reproduction steps", writeup)
            self.assertIn("## Evidence excerpts", writeup)
            self.assertIn(report["evidence_refs"][0], writeup)
            finding_record = json.loads(service.evidence.read(report["finding_ref"]).decode("utf-8"))
            finding_schema = json.loads((BASE / "schemas/finding.schema.json").read_text(encoding="utf-8"))
            validate(finding_record, finding_schema)
            self.assertTrue(finding_record["reviewer_run_id"].startswith("run_"))

    def test_reporter_is_mandatory_after_inconclusive_attack(self):
        case = self.cases["reporter-runs-after-inconclusive-attack"]
        with tempfile.TemporaryDirectory() as tmp:
            store, task = self.make_store(tmp)
            calls = []
            agents = {
                "recon": lambda *_: calls.append("recon") or {"facts": []},
                "analyze": lambda *_: calls.append("analyze") or {"plan": []},
                "attacker": lambda *_: calls.append("attacker") or {"result": "INCONCLUSIVE"},
                "reporter": lambda *_: calls.append("reporter") or {"verdict": "needs_more_evidence", "evidence_reviewed": [], "evidence_refs": []},
            }
            result = Orchestrator(store, agents, lambda *_: True).run(task["task_id"])
            self.assertEqual(result["status"], case["expected_status"])
            self.assertEqual(calls, case["expected_stages"])

    def test_reporter_feedback_runs_a_bounded_retry_cycle(self):
        case = self.cases["reporter-feedback-runs-one-bounded-cycle"]
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.sqlite3")
            task = store.create({"base_url": "https://example.org/"}, {"approved": True},
                                budget={"max_workflow_retries": 1})
            calls = {name: 0 for name in ("recon", "analyze", "attacker", "reporter")}

            def stage(name, result):
                def run(*_args):
                    calls[name] += 1
                    return result(calls[name]) if callable(result) else result
                return run

            agents = {
                "recon": stage("recon", {"facts": []}),
                "analyze": stage("analyze", {"plan": []}),
                "attacker": stage("attacker", {"result": "INCONCLUSIVE"}),
                "reporter": stage("reporter", lambda count: {
                    "verdict": "needs_more_evidence" if count == 1 else "accepted",
                    "evidence_reviewed": [] if count == 1 else ["ev_reviewed"],
                    "evidence_refs": [] if count == 1 else ["ev_reviewed"],
                }),
            }
            result = Orchestrator(store, agents, lambda *_: True).run(task["task_id"])
            self.assertEqual(result["status"], case["expected_status"])
            self.assertEqual(result["workflow_retry_count"], case["expected_retry_count"])
            self.assertEqual({key: calls[key] for key in case["expected_stage_runs"]},
                             case["expected_stage_runs"])
            self.assertIn(("REPORT_RUNNING", "ANALYZE_RUNNING"),
                          [(item["old_state"], item["new_state"]) for item in store.timeline(task["task_id"])])

    def test_reporter_cannot_accept_without_independent_evidence(self):
        case = self.cases["accepted-without-independent-evidence-is-partial"]
        with tempfile.TemporaryDirectory() as tmp:
            store, task = self.make_store(tmp)
            agents = {"recon": lambda *_: {}, "analyze": lambda *_: {}, "attacker": lambda *_: {},
                      "reporter": lambda *_: {"verdict": "accepted", "evidence_reviewed": [], "evidence_refs": []}}
            result = Orchestrator(store, agents, lambda *_: True).run(task["task_id"])
            self.assertEqual(result["status"], case["expected_status"])

    def test_reporter_cannot_accept_without_supporting_evidence_refs(self):
        case = self.cases["accepted-without-supporting-evidence-refs-is-partial"]
        with tempfile.TemporaryDirectory() as tmp:
            store, task = self.make_store(tmp)
            agents = {"recon": lambda *_: {}, "analyze": lambda *_: {}, "attacker": lambda *_: {},
                      "reporter": lambda *_: {"verdict": "accepted", "evidence_reviewed": ["ev_1"],
                                               "evidence_refs": []}}
            result = Orchestrator(store, agents, lambda *_: True).run(task["task_id"])
            self.assertEqual(result["status"], case["expected_status"])

    def test_fixture_covers_all_workflow_stages(self):
        covered = set().union(*(set(case["expected_stages"]) for case in self.fixture["cases"]))
        self.assertEqual(covered, {"recon", "analyze", "attacker", "reporter", "commander"})

    def test_recovery_keeps_saved_attacker_result_and_runs_reporter_only(self):
        case = self.cases["recovery-does-not-replay-saved-attacker"]
        with tempfile.TemporaryDirectory() as tmp:
            store, task = self.make_store(tmp)
            for state in ("VALIDATING_SCOPE", "RECON_RUNNING"):
                store.transition(task["task_id"], state, "fixture")
            store.save_result(task["task_id"], "recon", {})
            store.transition(task["task_id"], "ANALYZE_RUNNING", "fixture")
            store.save_result(task["task_id"], "analyze", {})
            store.transition(task["task_id"], "ATTACK_RUNNING", "fixture")
            store.save_result(task["task_id"], "attacker", {"result": "INCONCLUSIVE"})
            store.transition(task["task_id"], "REPORT_RUNNING", "fixture")
            store.recover(task["task_id"])
            calls = []
            orch = Orchestrator(store, {"reporter": lambda *_: calls.append("reporter") or {
                "verdict": "needs_more_evidence", "evidence_reviewed": [], "evidence_refs": []}}, lambda *_: True)
            result = orch.resume(task["task_id"])
            self.assertEqual(result["status"], case["expected_status"])
            self.assertEqual(calls, case["expected_stages"])

    def test_recovery_does_not_repeat_an_unconfirmed_attack(self):
        case = self.cases["recovery-blocks-uncertain-attacker-replay"]
        with tempfile.TemporaryDirectory() as tmp:
            store, task = self.make_store(tmp)
            for state in ("VALIDATING_SCOPE", "RECON_RUNNING"):
                store.transition(task["task_id"], state, "fixture")
            store.save_result(task["task_id"], "recon", {})
            store.transition(task["task_id"], "ANALYZE_RUNNING", "fixture")
            store.save_result(task["task_id"], "analyze", {})
            store.transition(task["task_id"], "ATTACK_RUNNING", "fixture")
            store.recover(task["task_id"])
            with self.assertRaises(RuntimeError):
                store.prepare_resume(task["task_id"])
            self.assertEqual(case["expected_status"], "MANUAL_REVIEW")

    def test_recovery_resumes_feedback_cycle_after_saved_attack_at_reporter(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.sqlite3")
            task = store.create({"base_url": "https://example.org/"}, {"approved": True},
                                budget={"max_workflow_retries": 1})
            for state in ("VALIDATING_SCOPE", "RECON_RUNNING"):
                store.transition(task["task_id"], state, "fixture")
            store.save_result(task["task_id"], "recon", {"facts": []})
            store.transition(task["task_id"], "ANALYZE_RUNNING", "fixture")
            store.save_result(task["task_id"], "analyze", {"plan": []})
            store.transition(task["task_id"], "ATTACK_RUNNING", "fixture")
            store.save_result(task["task_id"], "attacker", {"result": "INCONCLUSIVE"})
            store.transition(task["task_id"], "REPORT_RUNNING", "fixture")
            store.save_result(task["task_id"], "reporter", {"verdict": "needs_more_evidence"})

            store.begin_retry_cycle(task["task_id"])
            store.transition(task["task_id"], "ANALYZE_RUNNING", "feedback retry")
            store.mark_active_stage(task["task_id"], "analyze", retry_cycle=True)
            analyze_run = store.start_run(task["task_id"], "analyze", {})
            store.save_result(task["task_id"], "analyze", {"plan": ["refined"]})
            store.finish_run(analyze_run, result={"plan": ["refined"]})
            store.transition(task["task_id"], "ATTACK_RUNNING", "feedback retry")
            store.mark_active_stage(task["task_id"], "attacker", retry_cycle=True)
            attacker_run = store.start_run(task["task_id"], "attacker", {})
            store.save_result(task["task_id"], "attacker", {"result": "INCONCLUSIVE"})
            store.finish_run(attacker_run, result={"result": "INCONCLUSIVE"})
            store.recover(task["task_id"])
            calls = []
            orchestrator = Orchestrator(store, {
                "reporter": lambda *_: calls.append("reporter") or {
                    "verdict": "needs_more_evidence", "evidence_reviewed": [], "evidence_refs": []}},
                lambda *_: True)
            result = orchestrator.resume(task["task_id"])
            self.assertEqual(result["status"], "COMPLETED")
            self.assertEqual(calls, ["reporter"])
            self.assertEqual(result["workflow_retry_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
