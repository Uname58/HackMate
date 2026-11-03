"""SQLite-backed immutable evidence index and content-addressed artifact store."""
import hashlib
import json
import os
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

from ..schema_validation import SCHEMA_DIR, validate

_EVIDENCE_SCHEMA = json.loads((SCHEMA_DIR / "evidence.schema.json").read_text(encoding="utf-8"))


class EvidenceRepository:
    def __init__(self, root, database=None):
        self.root = Path(root).resolve()
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.database = Path(database or self.root / "evidence.sqlite3")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, kind TEXT NOT NULL,
                source_agent TEXT NOT NULL, captured_at REAL NOT NULL, storage_ref TEXT NOT NULL,
                sha256 TEXT NOT NULL, content_type TEXT, redaction_status TEXT NOT NULL,
                metadata_json TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS evidence_task_idx ON evidence(task_id)")

    @contextmanager
    def _connect(self):
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

    def put(self, task_id, kind, source_agent, content, content_type="application/octet-stream",
            redaction_status="pending", metadata=None):
        if isinstance(content, str):
            content = content.encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        rel = Path("artifacts") / task_id / digest[:2] / digest
        target = (self.root / rel).resolve()
        if not target.is_relative_to(self.artifacts):
            raise ValueError("invalid evidence path")
        evidence_id = "ev_" + digest[:16] + "_" + uuid.uuid4().hex[:12]
        captured = time.time()
        record = {
            "evidence_id": evidence_id,
            "task_id": str(task_id),
            "kind": str(kind),
            "source_agent": str(source_agent),
            "captured_at": datetime.fromtimestamp(captured, timezone.utc).isoformat(),
            "storage_ref": str(rel).replace("\\", "/"),
            "sha256": digest,
            "content_type": content_type,
            "redaction_status": str(redaction_status),
            "metadata": metadata or {},
        }
        validate(record, _EVIDENCE_SCHEMA)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                os.replace(tmp_name, target)
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        with self._connect() as db:
            db.execute("INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (evidence_id, task_id, kind, source_agent, captured, str(rel), digest,
                        content_type, redaction_status,
                        json.dumps(metadata or {}, ensure_ascii=False)))
        return self.get(evidence_id)

    def get(self, evidence_id):
        with self._connect() as db:
            row = db.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        item = dict(row)
        item["captured_at"] = datetime.fromtimestamp(item["captured_at"], timezone.utc).isoformat()
        item["metadata"] = json.loads(item.pop("metadata_json"))
        validate(item, _EVIDENCE_SCHEMA)
        return item

    def read(self, evidence_id):
        item = self.get(evidence_id)
        path = (self.root / item["storage_ref"]).resolve()
        if not path.is_relative_to(self.artifacts) or not path.is_file():
            raise FileNotFoundError(item["storage_ref"])
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise IOError("evidence digest mismatch")
        return data

    def list_task(self, task_id):
        with self._connect() as db:
            ids = [r[0] for r in db.execute(
                "SELECT evidence_id FROM evidence WHERE task_id=? ORDER BY captured_at", (task_id,))]
        return [self.get(eid) for eid in ids]
