"""SQLite persistence, transactional approval, and idempotent simulated effects."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from aegisflow.models import Incident
from aegisflow.playbooks import phishing_playbook


def now():
    return datetime.now(timezone.utc).isoformat()


def plan_digest(incident: Incident) -> str:
    data = json.dumps([a.model_dump() for a in incident.actions], sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS simulation_effects (
                    incident_id TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL,
                    timestamp TEXT NOT NULL, PRIMARY KEY(incident_id,kind,target));
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, incident_id: str) -> Incident | None:
        with self.connection() as db:
            row = db.execute("SELECT record FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row["record"]) if row else None

    def save(self, incident: Incident) -> Incident:
        with self.connection() as db:
            result = db.execute(
                "INSERT OR IGNORE INTO incidents VALUES (?,?)", (incident.id, incident.model_dump_json())
            )
            if result.rowcount:
                self._audit(
                    db,
                    incident.id,
                    "incident_investigated",
                    {
                        "mode": incident.mode,
                        "severity": incident.severity,
                        "status": incident.status,
                        "actions": len(incident.actions),
                        "simulation": True,
                    },
                )
        return self.get(incident.id)

    def list(self) -> list[Incident]:
        with self.connection() as db:
            rows = db.execute("SELECT record FROM incidents ORDER BY rowid DESC LIMIT 100").fetchall()
        return [Incident.model_validate_json(row["record"]) for row in rows]

    def timeline(self, incident_id: str) -> list[dict]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT timestamp,event,details FROM audit WHERE incident_id=? ORDER BY id", (incident_id,)
            ).fetchall()
        return [{"timestamp": r["timestamp"], "event": r["event"], "details": json.loads(r["details"])} for r in rows]

    @staticmethod
    def _audit(db, incident_id, event, details):
        db.execute(
            "INSERT INTO audit(incident_id,timestamp,event,details) VALUES (?,?,?,?)",
            (incident_id, now(), event, json.dumps(details)),
        )

    def decide(self, incident_id: str, decision: str, analyst: str, note: str, expected_digest: str) -> Incident:
        if decision not in {"approve", "dismiss"}:
            raise ValueError("Decision must be approve or dismiss.")
        analyst, note = analyst.strip(), note.strip()
        if not analyst or len(analyst) > 80 or not note or len(note) > 500:
            raise ValueError("Enter an analyst name (1–80 characters) and note (1–500 characters).")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT record FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not row:
                raise ValueError("Incident does not exist.")
            incident = Incident.model_validate_json(row["record"])
            if incident.status != "review_required":
                raise ValueError("Incident already has a final decision; effects cannot be repeated.")
            if plan_digest(incident) != expected_digest:
                raise ValueError("Plan changed. Refresh and review it before approving.")
            if decision == "approve" and not incident.actions:
                raise ValueError("There are no containment actions to approve. Dismiss after review instead.")
            allowed = set(phishing_playbook()["allowed_actions"])
            known_evidence = {e.id for e in incident.evidence}
            for action in incident.actions:
                if (
                    action.kind not in allowed
                    or not action.evidence_ids
                    or not set(action.evidence_ids).issubset(known_evidence)
                ):
                    raise ValueError("Action failed playbook/evidence validation.")
            self._audit(
                db,
                incident_id,
                "analyst_" + decision,
                {"analyst": analyst, "note": note, "plan_sha256": expected_digest, "simulation": True},
            )
            if decision == "approve":
                for action in incident.actions:
                    db.execute(
                        "INSERT INTO simulation_effects VALUES (?,?,?,?)",
                        (incident_id, action.kind, action.target, now()),
                    )
                    self._audit(
                        db,
                        incident_id,
                        "simulated_" + action.kind,
                        {"target": action.target, "evidence_ids": action.evidence_ids, "result": "simulated_success"},
                    )
                incident.status = "contained"
            else:
                incident.status = "dismissed"
            db.execute("UPDATE incidents SET record=? WHERE id=?", (incident.model_dump_json(), incident_id))
        return incident

    def effects(self, incident_id: str) -> list[dict]:
        with self.connection() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT kind,target,timestamp FROM simulation_effects WHERE incident_id=?", (incident_id,)
                )
            ]
