"""Audited Research candidate lifecycle; never writes formal Skills directly."""
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .schema_validation import SCHEMA_DIR, validate


class ResearchRepository:
    """Persist source-backed candidate knowledge and enforce promotion gates."""

    VALIDATION_EVIDENCE_KINDS = {
        "http_request", "http_response", "cdp_event", "browser_screenshot", "tool_output",
    }

    def __init__(self, database, evidence_repo):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.evidence = evidence_repo
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS candidates (
                candidate_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, status TEXT NOT NULL,
                payload_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS candidate_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_id TEXT NOT NULL,
                from_status TEXT, to_status TEXT NOT NULL, actor TEXT NOT NULL,
                note TEXT NOT NULL, timestamp TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS candidate_task_idx ON candidates(task_id)")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(str(self.database), timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def capture_source(self, task_id, url, title, content, source_agent="research"):
        """Save retrieved source text as immutable evidence for a candidate."""
        parsed = urlsplit(str(url or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("research source must be an HTTP(S) URL without embedded credentials")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("research source content is empty")
        if len(content.encode("utf-8")) > 1_000_000:
            raise ValueError("research source exceeds the 1 MB capture limit")
        return self.evidence.put(
            task_id, "research_source", source_agent, content,
            content_type="text/plain; charset=utf-8", redaction_status="pending",
            metadata={"url": url, "title": str(title or "")})

    def create(self, task_id, vulnerability_type, title, claim, proposed_knowledge,
               source_refs, validation_plan):
        if not isinstance(source_refs, (list, tuple)) or not isinstance(validation_plan, (list, tuple)):
            raise ValueError("source_refs and validation_plan must be arrays")
        source_refs = list(dict.fromkeys(source_refs or []))
        validation_plan = list(validation_plan or [])
        self._check_evidence_refs(source_refs, task_id, expected_kind="research_source")
        now = self._now()
        candidate = {
            "schema_version": "1.0.0",
            "candidate_id": "research_" + uuid.uuid4().hex,
            "task_id": str(task_id),
            "vulnerability_type": str(vulnerability_type or "").strip(),
            "title": str(title or "").strip(),
            "claim": str(claim or "").strip(),
            "proposed_knowledge": str(proposed_knowledge or "").strip(),
            "source_refs": source_refs,
            "validation_plan": validation_plan,
            "status": "proposed",
            "validation_evidence_refs": [],
            "validation_notes": "",
            "eval_ref": None,
            "approved_by": None,
            "promotion_ref": None,
            "rejection_reason": None,
            "created_at": now,
            "updated_at": now,
        }
        self._validate(candidate)
        with self._db() as db:
            db.execute("INSERT INTO candidates VALUES(?,?,?,?,?,?)",
                       (candidate["candidate_id"], task_id, candidate["status"],
                        json.dumps(candidate, ensure_ascii=False), now, now))
            self._event(db, candidate["candidate_id"], None, "proposed", "research",
                        "candidate created with source evidence", now)
        return candidate

    def get(self, candidate_id):
        with self._db() as db:
            row = db.execute("SELECT payload_json FROM candidates WHERE candidate_id=?",
                             (candidate_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, task_id=None, limit=100):
        with self._db() as db:
            if task_id:
                rows = db.execute("SELECT payload_json FROM candidates WHERE task_id=? ORDER BY created_at DESC LIMIT ?",
                                  (task_id, max(1, min(500, int(limit))))).fetchall()
            else:
                rows = db.execute("SELECT payload_json FROM candidates ORDER BY created_at DESC LIMIT ?",
                                  (max(1, min(500, int(limit))),)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def record_validation(self, candidate_id, evidence_refs, passed, notes):
        if not isinstance(passed, bool):
            raise TypeError("validation result must be a boolean")
        if not isinstance(evidence_refs, (list, tuple)):
            raise ValueError("validation evidence references must be an array")
        candidate = self._required(candidate_id, "proposed")
        refs = list(dict.fromkeys(evidence_refs or []))
        if passed and not refs:
            raise ValueError("successful controlled validation requires raw evidence references")
        self._check_evidence_refs(refs, candidate["task_id"])
        if passed and any(self.evidence.get(ref)["kind"] not in self.VALIDATION_EVIDENCE_KINDS
                          for ref in refs):
            raise ValueError("controlled validation must cite raw request/response, browser, CDP, or tool evidence")
        if not str(notes or "").strip():
            raise ValueError("validation notes are required")
        candidate["validation_evidence_refs"] = refs
        candidate["validation_notes"] = str(notes).strip()
        new_status = "validated" if passed else "rejected"
        if not passed:
            candidate["rejection_reason"] = "controlled validation failed"
        return self._save(candidate, new_status, "validator", candidate["validation_notes"])

    def record_eval(self, candidate_id, passed, summary, details=None):
        if not isinstance(passed, bool):
            raise TypeError("Eval result must be a boolean")
        candidate = self._required(candidate_id, "validated")
        summary = str(summary or "").strip()
        if not summary:
            raise ValueError("Eval summary is required")
        details = details if isinstance(details, dict) else {}
        if passed:
            before = details.get("before") or {}
            after = details.get("candidate") or {}
            skill_ref = str(details.get("skill_ref") or "").strip()
            try:
                base_reg, base_hidden = float(before["regression"]), float(before["hidden"])
                new_reg, new_hidden = float(after["regression"]), float(after["hidden"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("passing Eval requires recorded regression/hidden baseline and candidate scores") from exc
            if not skill_ref:
                raise ValueError("passing Eval must bind to an existing Skill target")
            if (new_reg < base_reg or new_hidden < base_hidden - 0.05 or
                    (new_reg + new_hidden) / 2 - (base_reg + base_hidden) / 2 < 0.02):
                raise ValueError("reported Eval scores do not meet the candidate acceptance thresholds")
        evaluation = {"candidate_id": candidate_id, "passed": bool(passed), "summary": summary,
                      "details": details,
                      "validation_evidence_refs": candidate["validation_evidence_refs"]}
        artifact = self.evidence.put(
            candidate["task_id"], "evaluation", "eval", json.dumps(evaluation, ensure_ascii=False),
            content_type="application/json", redaction_status="pending",
            metadata={"candidate_id": candidate_id})
        candidate["eval_ref"] = artifact["evidence_id"]
        new_status = "eval_passed" if passed else "rejected"
        if not passed:
            candidate["rejection_reason"] = "candidate failed Eval"
        return self._save(candidate, new_status, "eval", summary)

    def approve(self, candidate_id, approved_by):
        candidate = self._required(candidate_id, "eval_passed")
        approved_by = str(approved_by or "").strip()
        if not approved_by:
            raise ValueError("an explicit human approver is required")
        candidate["approved_by"] = approved_by
        return self._save(candidate, "approved", approved_by, "explicit approval to promote candidate")

    def reject(self, candidate_id, reason, rejected_by="user"):
        candidate = self.get(candidate_id)
        if candidate is None:
            raise KeyError(candidate_id)
        if candidate["status"] in {"promoted", "rejected"}:
            raise ValueError(f"cannot reject a {candidate['status']} candidate")
        reason = str(reason or "").strip()
        rejected_by = str(rejected_by or "").strip()
        if not reason or not rejected_by:
            raise ValueError("rejection reason and reviewer are required")
        candidate["rejection_reason"] = reason
        return self._save(candidate, "rejected", str(rejected_by), reason)

    def promote(self, candidate_id, skill_update):
        """Run an existing Eval-gated Skill update only after human approval."""
        candidate = self._required(candidate_id, "approved")
        if not callable(skill_update):
            raise TypeError("skill_update must be an Eval-gated update callback")
        self._record_event(candidate_id, "approved", "approved", "skill_eval",
                           "promotion attempt started after explicit approval")
        try:
            outcome = skill_update(dict(candidate))
        except Exception as exc:
            self._record_event(candidate_id, "approved", "approved", "skill_eval",
                               f"Skill update callback failed: {type(exc).__name__}: {exc}")
            raise
        if not isinstance(outcome, dict) or outcome.get("kept") is not True or not outcome.get("skill_ref"):
            self._record_event(candidate_id, "approved", "approved", "skill_eval",
                               "Skill gate did not keep this candidate; formal Skill was not promoted")
            return {"promoted": False, "candidate": self.get(candidate_id), "outcome": outcome}
        eval_ref = outcome.get("skill_eval_ref")
        if not eval_ref:
            self._record_event(candidate_id, "approved", "approved", "skill_eval",
                               "promotion refused because Skill Eval evidence was not attached")
            return {"promoted": False, "candidate": self.get(candidate_id), "outcome": outcome}
        self._check_evidence_refs([eval_ref], candidate["task_id"], expected_kind="skill_evaluation")
        eval_result = json.loads(self.evidence.read(eval_ref).decode("utf-8"))
        candidate_eval = json.loads(self.evidence.read(candidate["eval_ref"]).decode("utf-8"))
        if (eval_result.get("candidate_id") != candidate_id or
                eval_result.get("passed") is not True or
                eval_result.get("skill_ref") != outcome["skill_ref"] or
                candidate_eval.get("candidate_id") != candidate_id or
                candidate_eval.get("passed") is not True or
                candidate_eval.get("details", {}).get("skill_ref") != outcome["skill_ref"]):
            self._record_event(candidate_id, "approved", "approved", "skill_eval",
                               "promotion refused because Skill Eval evidence did not confirm the kept update")
            return {"promoted": False, "candidate": self.get(candidate_id), "outcome": outcome}
        candidate["promotion_ref"] = str(outcome["skill_ref"])
        saved = self._save(candidate, "promoted", "skill_eval",
                           f"existing Skill Eval gate kept update: {candidate['promotion_ref']} (evidence {eval_ref})")
        return {"promoted": True, "candidate": saved, "outcome": outcome}

    def capture_skill_eval(self, candidate_id, passed, skill_ref, summary):
        """Record the existing Skill gate result before marking a candidate promoted."""
        if not isinstance(passed, bool):
            raise TypeError("Skill Eval result must be a boolean")
        candidate = self._required(candidate_id, "approved")
        skill_ref = str(skill_ref or "").strip()
        summary = str(summary or "").strip()
        if not skill_ref or not summary:
            raise ValueError("skill reference and Eval summary are required")
        return self.evidence.put(
            candidate["task_id"], "skill_evaluation", "skill_eval",
            json.dumps({"candidate_id": candidate_id, "passed": bool(passed),
                        "skill_ref": skill_ref, "summary": summary}, ensure_ascii=False),
            content_type="application/json", redaction_status="pending",
            metadata={"candidate_id": candidate_id, "skill_ref": skill_ref})

    def timeline(self, candidate_id):
        with self._db() as db:
            rows = db.execute("SELECT from_status,to_status,actor,note,timestamp FROM candidate_events "
                              "WHERE candidate_id=? ORDER BY event_id", (candidate_id,)).fetchall()
        return [dict(row) for row in rows]

    def _check_evidence_refs(self, refs, task_id, expected_kind=None):
        for evidence_id in refs:
            item = self.evidence.get(evidence_id)
            if item["task_id"] != task_id:
                raise ValueError("research evidence must belong to the same task")
            if expected_kind and item["kind"] != expected_kind:
                raise ValueError(f"source evidence must have kind {expected_kind}")
            self.evidence.read(evidence_id)  # verify content-address digest before changing state

    def _required(self, candidate_id, expected_status):
        candidate = self.get(candidate_id)
        if candidate is None:
            raise KeyError(candidate_id)
        if candidate["status"] != expected_status:
            raise ValueError(f"candidate must be {expected_status}, got {candidate['status']}")
        return candidate

    def _validate(self, candidate):
        schema = json.loads((SCHEMA_DIR / "research_candidate.schema.json").read_text(encoding="utf-8"))
        validate(candidate, schema)

    def _save(self, candidate, new_status, actor, note):
        old_status = candidate["status"]
        candidate["status"] = new_status
        candidate["updated_at"] = self._now()
        self._validate(candidate)
        with self._db() as db:
            changed = db.execute("UPDATE candidates SET status=?,payload_json=?,updated_at=? "
                                 "WHERE candidate_id=? AND status=?",
                                 (new_status, json.dumps(candidate, ensure_ascii=False),
                                  candidate["updated_at"], candidate["candidate_id"], old_status)).rowcount
            if changed != 1:
                raise RuntimeError("candidate changed concurrently; reload before retrying")
            self._event(db, candidate["candidate_id"], old_status, new_status,
                        actor, note, candidate["updated_at"])
        return candidate

    def _record_event(self, candidate_id, old_status, new_status, actor, note):
        with self._db() as db:
            self._event(db, candidate_id, old_status, new_status, actor, note, self._now())

    @staticmethod
    def _event(db, candidate_id, old_status, new_status, actor, note, timestamp):
        db.execute("INSERT INTO candidate_events(candidate_id,from_status,to_status,actor,note,timestamp) "
                   "VALUES(?,?,?,?,?,?)", (candidate_id, old_status, new_status, actor, note, timestamp))
