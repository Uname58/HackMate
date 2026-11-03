"""Durable workflow state machine. Agent execution is injected; Python owns transitions."""
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

from ..agents.commander import summarize_task

STATES = {"CREATED", "VALIDATING_SCOPE", "RECON_RUNNING", "ANALYZE_RUNNING",
          "ATTACK_RUNNING", "REPORT_RUNNING", "COMPLETED", "PARTIAL", "BLOCKED",
          "FAILED", "CANCELLED"}
TERMINAL = {"COMPLETED", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED"}
TRANSITIONS = {
    "CREATED": {"VALIDATING_SCOPE", "CANCELLED"},
    "VALIDATING_SCOPE": {"RECON_RUNNING", "BLOCKED", "FAILED", "CANCELLED"},
    "RECON_RUNNING": {"ANALYZE_RUNNING", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED"},
    "ANALYZE_RUNNING": {"ATTACK_RUNNING", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED"},
    "ATTACK_RUNNING": {"REPORT_RUNNING", "ANALYZE_RUNNING", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED"},
    "REPORT_RUNNING": {"COMPLETED", "ANALYZE_RUNNING", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED"},
}


class TaskStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tasks(
                task_id TEXT PRIMARY KEY, status TEXT NOT NULL, data TEXT NOT NULL,
                created REAL NOT NULL, updated REAL NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS transitions(
                id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
                old_state TEXT, new_state TEXT NOT NULL, reason TEXT NOT NULL,
                actor TEXT NOT NULL, run_id TEXT, timestamp REAL NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS runs(
                run_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, agent TEXT NOT NULL,
                status TEXT NOT NULL, input_json TEXT NOT NULL, output_json TEXT,
                started REAL NOT NULL, completed REAL, error TEXT)""")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def create(self, target, scope, budget=None, user_request=""):
        task_id = "task_" + uuid.uuid4().hex
        now = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        data = {"schema_version": "1.0.0", "task_id": task_id, "status": "CREATED", "target": target,
                "scope": scope, "budget": budget or {}, "user_request": user_request,
                "results": {}, "results_history": {}, "workflow_retry_count": 0,
                "workflow_retry_active": False, "workflow_retry_next_stage": None,
                "active_stage": None, "active_stage_completed": False,
                "created_at": now_iso, "updated_at": now_iso}
        with self._db() as db:
            db.execute("INSERT INTO tasks VALUES(?,?,?,?,?)",
                       (task_id, "CREATED", json.dumps(data), now, now))
            db.execute("INSERT INTO transitions(task_id,old_state,new_state,reason,actor,timestamp) VALUES(?,?,?,?,?,?)",
                       (task_id, None, "CREATED", "task created", "commander", now))
        return data

    def get(self, task_id):
        with self._db() as db:
            row = db.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def transition(self, task_id, new_state, reason, actor="orchestrator", run_id=None):
        if new_state not in STATES:
            raise ValueError("unknown task state")
        with self._db() as db:
            row = db.execute("SELECT status,data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            old = row["status"]
            if new_state not in TRANSITIONS.get(old, set()):
                raise ValueError(f"illegal transition {old} -> {new_state}")
            data = json.loads(row["data"])
            now = time.time()
            data["status"] = new_state
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            db.execute("UPDATE tasks SET status=?,data=?,updated=? WHERE task_id=?",
                       (new_state, json.dumps(data), now, task_id))
            db.execute("INSERT INTO transitions(task_id,old_state,new_state,reason,actor,run_id,timestamp) VALUES(?,?,?,?,?,?,?)",
                       (task_id, old, new_state, reason, actor, run_id, now))
            return data

    def save_result(self, task_id, stage, result):
        with self._db() as db:
            row = db.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            data = json.loads(row[0])
            data["results"][stage] = result
            data.setdefault("results_history", {}).setdefault(stage, []).append({
                "run_id": data.get("active_run_id"), "result": result,
                "saved_at": datetime.now(timezone.utc).isoformat()})
            if data.get("active_stage") == stage:
                data["active_stage_completed"] = True
            if data.get("workflow_retry_active") and stage in {"analyze", "attacker", "reporter"}:
                next_stage = {"analyze": "attacker", "attacker": "reporter", "reporter": None}[stage]
                data["workflow_retry_next_stage"] = next_stage
                if next_stage is None:
                    data["workflow_retry_active"] = False
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            db.execute("UPDATE tasks SET data=?,updated=? WHERE task_id=?",
                       (json.dumps(data), time.time(), task_id))
            return data

    def mark_active_stage(self, task_id, stage, retry_cycle=False):
        with self._db() as db:
            row = db.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            data = json.loads(row[0])
            data["active_stage"] = stage
            data["active_stage_completed"] = False
            if retry_cycle:
                data["workflow_retry_active"] = True
                data["workflow_retry_next_stage"] = stage
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            db.execute("UPDATE tasks SET data=?,updated=? WHERE task_id=?",
                       (json.dumps(data), time.time(), task_id))

    def begin_retry_cycle(self, task_id):
        with self._db() as db:
            row = db.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            data = json.loads(row[0])
            data["workflow_retry_count"] = int(data.get("workflow_retry_count", 0)) + 1
            data["workflow_retry_active"] = True
            data["workflow_retry_next_stage"] = "analyze"
            data["active_stage"] = None
            data["active_stage_completed"] = False
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            db.execute("UPDATE tasks SET data=?,updated=? WHERE task_id=?",
                       (json.dumps(data), time.time(), task_id))
            return data["workflow_retry_count"]

    def add_token_usage(self, task_id, tokens, mode="reported"):
        with self._db() as db:
            row = db.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            data = json.loads(row[0])
            usage = data.setdefault("budget_usage", {"tokens": 0, "mode": mode})
            usage["tokens"] += int(tokens)
            if mode == "estimated":
                usage["mode"] = "estimated"
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            db.execute("UPDATE tasks SET data=?,updated=? WHERE task_id=?",
                       (json.dumps(data), time.time(), task_id))
            return usage

    def save_gate_state(self, task_id, state):
        """Persist request quotas and DNS observations for safe task recovery."""
        with self._db() as db:
            row = db.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            data = json.loads(row[0])
            data["scope_gate_state"] = state
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            db.execute("UPDATE tasks SET data=?,updated=? WHERE task_id=?",
                       (json.dumps(data), time.time(), task_id))

    def get_gate_state(self, task_id):
        task = self.get(task_id)
        if task is None:
            raise KeyError(task_id)
        return task.get("scope_gate_state", {})

    def start_run(self, task_id, agent, inputs):
        run_id, now = "run_" + uuid.uuid4().hex, time.time()
        with self._db() as db:
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?)",
                       (run_id, task_id, agent, "running", json.dumps(inputs), None, now, None, None))
            row = db.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if row:
                data = json.loads(row[0])
                data["active_run_id"] = run_id
                data["updated_at"] = datetime.now(timezone.utc).isoformat()
                db.execute("UPDATE tasks SET data=?,updated=? WHERE task_id=?",
                           (json.dumps(data), now, task_id))
        return run_id

    def finish_run(self, run_id, result=None, error=None):
        with self._db() as db:
            db.execute("UPDATE runs SET status=?,output_json=?,completed=?,error=? WHERE run_id=?",
                       ("failed" if error else "completed", json.dumps(result) if result is not None else None,
                        time.time(), error, run_id))

    def recover(self, task_id):
        """Mark a process-interrupted run recoverable without guessing completion."""
        with self._db() as db:
            row = db.execute("SELECT status,data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            data = json.loads(row["data"])
            now = time.time()
            db.execute("UPDATE runs SET status='failed',error='process interrupted',completed=? "
                       "WHERE task_id=? AND status='running'", (now, task_id))
            if row["status"] not in TERMINAL:
                data["recovery_required"] = True
                data["interrupted_state"] = row["status"]
                data["status"] = "PARTIAL"
                data["updated_at"] = datetime.now(timezone.utc).isoformat()
                db.execute("UPDATE tasks SET status='PARTIAL',data=?,updated=? WHERE task_id=?",
                           (json.dumps(data), now, task_id))
                db.execute("INSERT INTO transitions(task_id,old_state,new_state,reason,actor,timestamp) VALUES(?,?,?,?,?,?)",
                           (task_id, row["status"], "PARTIAL", "process interruption; inspect prior evidence before resuming", "recovery", now))
            return data

    def prepare_resume(self, task_id):
        """Prepare an explicitly requested, audited resume from the first missing safe stage."""
        with self._db() as db:
            row = db.execute("SELECT status,data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            if row["status"] != "PARTIAL":
                raise ValueError("only recovered PARTIAL tasks can resume")
            data = json.loads(row["data"])
            if not data.get("recovery_required"):
                raise ValueError("task is not marked for recovery")
            done = data.get("results", {})
            if (data.get("active_stage") == "attacker" and
                    not data.get("active_stage_completed")) or (
                    data.get("interrupted_state") == "ATTACK_RUNNING" and "attacker" not in done):
                raise RuntimeError("Attacker was interrupted before its result was saved; inspect evidence and create a reviewed retry task")
            if data.get("workflow_retry_active"):
                pending = data.get("workflow_retry_next_stage")
                states = {"analyze": "ANALYZE_RUNNING", "attacker": "ATTACK_RUNNING",
                          "reporter": "REPORT_RUNNING"}
                if pending not in states:
                    raise RuntimeError("recovered retry cycle has no safe next stage")
                resume_state = states[pending]
            else:
                stages = Orchestrator.STAGES
                index = next((i for i, (agent, _) in enumerate(stages) if agent not in done), len(stages))
                if index == len(stages):
                    resume_state = "REPORT_RUNNING"
                elif index == 0:
                    resume_state = "VALIDATING_SCOPE"
                else:
                    resume_state = stages[index - 1][1]
            now = time.time()
            data["recovery_required"] = False
            data["resumed_at"] = now
            data["status"] = resume_state
            old = row["status"]
            db.execute("UPDATE tasks SET status=?,data=?,updated=? WHERE task_id=?",
                       (resume_state, json.dumps(data), now, task_id))
            db.execute("INSERT INTO transitions(task_id,old_state,new_state,reason,actor,timestamp) VALUES(?,?,?,?,?,?)",
                       (task_id, old, resume_state, "explicit recovery resume; completed stages retained", "commander", now))
            return data

    def timeline(self, task_id):
        with self._db() as db:
            rows = db.execute("SELECT old_state,new_state,reason,actor,run_id,timestamp FROM transitions WHERE task_id=? ORDER BY id",
                              (task_id,)).fetchall()
        return [dict(row) for row in rows]

    def list_tasks(self, limit=50):
        with self._db() as db:
            rows = db.execute("SELECT data FROM tasks ORDER BY created DESC LIMIT ?", (int(limit),)).fetchall()
        return [json.loads(row[0]) for row in rows]


class Orchestrator:
    """Sequential orchestration with mandatory scope validation and independent report stage.

    ``agents`` maps recon/analyze/attacker/reporter to callables(task, prior_results).
    ``scope_validator`` and every tool adapter must enforce policy separately.
    """
    STAGES = [("recon", "RECON_RUNNING"), ("analyze", "ANALYZE_RUNNING"),
              ("attacker", "ATTACK_RUNNING"), ("reporter", "REPORT_RUNNING")]

    def __init__(self, store, agents, scope_validator):
        self.store, self.agents, self.scope_validator = store, agents, scope_validator

    def run(self, task_id, cancel_check=None):
        task = self.store.get(task_id)
        if task is None:
            raise KeyError(task_id)
        if task["status"] != "CREATED":
            raise ValueError("only newly created tasks can be run")
        self.store.transition(task_id, "VALIDATING_SCOPE", "validate explicit authorization")
        try:
            self.scope_validator(task["scope"], task["target"])
        except Exception as exc:
            self.store.transition(task_id, "BLOCKED", str(exc), actor="scope_gate")
            self._write_commander(task_id, {}, "BLOCKED")
            return self.store.get(task_id)
        return self._continue(task_id, task, {}, cancel_check)

    def _write_commander(self, task_id, reporter, status):
        run_id = self.store.start_run(
            task_id, "commander", {"task_id": task_id,
                                    "reporter_verdict": reporter.get("verdict", "missing")})
        result = summarize_task(task_id, reporter, status)
        self.store.save_result(task_id, "commander", result)
        self.store.finish_run(run_id, result=result)
        return result

    def resume(self, task_id, cancel_check=None):
        task = self.store.get(task_id)
        if task is None:
            raise KeyError(task_id)
        if not task.get("recovery_required"):
            raise ValueError("task has no pending recovery")
        self.scope_validator(task["scope"], task["target"])
        task = self.store.prepare_resume(task_id)
        task = self.store.get(task_id)
        return self._continue(task_id, task, dict(task.get("results", {})), cancel_check)

    def _continue(self, task_id, task, results, cancel_check):
        started = task.get("created_at", time.time())
        if isinstance(started, str):
            started = datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
        duration_limit = int(task.get("budget", {}).get("max_duration_seconds", 0) or 0)

        def stop(status, reason, actor="commander", run_id=None):
            current = self.store.get(task_id)["status"]
            if current != status:
                self.store.transition(task_id, status, reason, actor=actor, run_id=run_id)
            self._write_commander(task_id, results.get("reporter", {}), status)
            return self.store.get(task_id)

        def run_stage(agent, state, retry_cycle=False):
            current_task = self.store.get(task_id)
            if cancel_check and cancel_check():
                return stop("CANCELLED", "cancel requested between workflow stages")
            if duration_limit and time.time() - started > duration_limit:
                return stop("PARTIAL", "task time budget exhausted")
            if current_task["status"] != state:
                self.store.transition(task_id, state, f"start {agent}", actor="commander")
            self.store.mark_active_stage(task_id, agent, retry_cycle=retry_cycle)
            run_id = self.store.start_run(task_id, agent,
                                          {"task_id": task_id, "prior_results": results,
                                           "retry_count": current_task.get("workflow_retry_count", 0)})
            try:
                if agent not in self.agents:
                    raise RuntimeError(f"agent adapter not configured: {agent}")
                stage_task = self.store.get(task_id)
                stage_task["current_run_id"] = run_id
                output = self.agents[agent](stage_task, dict(results))
                if cancel_check and cancel_check():
                    self.store.finish_run(run_id, error="cancelled after stage output; review evidence before retry")
                    self.store.transition(task_id, "CANCELLED", "cancel requested after stage output", actor="commander", run_id=run_id)
                    self._write_commander(task_id, results.get("reporter", {}), "CANCELLED")
                    return self.store.get(task_id)
                if not isinstance(output, dict):
                    raise TypeError(f"{agent} output must be a dict")
                results[agent] = output
                self.store.save_result(task_id, agent, output)
                self.store.finish_run(run_id, result=output)
            except Exception as exc:
                self.store.finish_run(run_id, error=f"{type(exc).__name__}: {exc}")
                if cancel_check and cancel_check():
                    terminal = "CANCELLED"
                    reason = "cancel requested during agent execution; inspect evidence before retry"
                else:
                    terminal = "PARTIAL" if results else "FAILED"
                    reason = f"{agent} failed: {exc}"
                self.store.transition(task_id, terminal, reason, actor=agent, run_id=run_id)
                self._write_commander(task_id, results.get("reporter", {}), terminal)
                return self.store.get(task_id)
            return None

        current_task = self.store.get(task_id)
        if current_task.get("workflow_retry_active"):
            retry_stages = [(agent, state) for agent, state in self.STAGES[1:]]
            next_stage = current_task.get("workflow_retry_next_stage")
            index = next((i for i, (agent, _) in enumerate(retry_stages) if agent == next_stage), None)
            if index is None:
                raise RuntimeError("retry recovery state has no valid next stage")
            stages_to_run = retry_stages[index:]
            retry_cycle = True
        else:
            stages_to_run = self.STAGES
            retry_cycle = False

        for agent, state in stages_to_run:
            if not retry_cycle and agent in results:
                continue
            stopped = run_stage(agent, state, retry_cycle=retry_cycle)
            if stopped is not None:
                return stopped

        max_retries = max(0, min(3, int(task.get("budget", {}).get("max_workflow_retries", 0) or 0)))
        retry_count = int(self.store.get(task_id).get("workflow_retry_count", 0))
        while (results.get("reporter", {}).get("verdict") == "needs_more_evidence" and
               retry_count < max_retries):
            retry_count = self.store.begin_retry_cycle(task_id)
            for agent, state in self.STAGES[1:]:
                stopped = run_stage(agent, state, retry_cycle=True)
                if stopped is not None:
                    return stopped
        report = results.get("reporter", {})
        verdict = report.get("verdict")
        if verdict == "accepted" and (not report.get("evidence_reviewed") or
                                       not report.get("evidence_refs") or
                                       not set(report.get("evidence_refs", [])).issubset(set(report.get("evidence_reviewed", [])))):
            terminal = "PARTIAL"
        else:
            terminal = "COMPLETED" if verdict in ("accepted", "rejected", "needs_more_evidence") else "PARTIAL"
        self._write_commander(task_id, report, terminal)
        self.store.transition(task_id, terminal, f"Reporter verdict: {verdict or 'missing'}", actor="commander")
        return self.store.get(task_id)
