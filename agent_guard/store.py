"""SQLite store: ticks for the sparkline, incidents for the timeline, actions for
the audit trail.

Deliberately boring: one file, no migrations until the shape actually changes,
and every write short enough to run inside a 10-minute tick.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .config import STATE_DIR, Config
from .remediate import Action
from .rules import Finding
from .sampler import Snapshot

SCHEMA = """
CREATE TABLE IF NOT EXISTS ticks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  load1 REAL, cores INTEGER,
  mem_used_mb INTEGER, mem_total_mb INTEGER,
  pressure REAL, swap_used_mb INTEGER, swap_total_mb INTEGER,
  top_json TEXT, duration_ms INTEGER
);
CREATE TABLE IF NOT EXISTS incidents (
  key TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  hint TEXT,
  pid INTEGER,
  value REAL,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  closed_at REAL,
  acked_at REAL,
  acked_by TEXT,
  escalated_at REAL
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT,
  ok INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_open ON incidents (closed_at);
CREATE INDEX IF NOT EXISTS actions_ts ON actions (ts);
"""


class Store:
    def __init__(self, path: Path | None = None) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = path or STATE_DIR / "agent-guard.db"
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # --- writes -----------------------------------------------------------
    def record_tick(self, snap: Snapshot, duration_ms: int) -> None:
        top = [
            {"pid": p.pid, "comm": p.comm, "cpu": round(p.cpu_pct, 1), "rss_mb": round(p.rss_mb, 1)}
            for p in snap.top(8)
        ]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO ticks (ts, load1, cores, mem_used_mb, mem_total_mb, pressure,"
                " swap_used_mb, swap_total_mb, top_json, duration_ms)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    snap.ts,
                    snap.load1,
                    snap.cores,
                    snap.mem_used_mb,
                    snap.mem_total_mb,
                    snap.pressure_some_avg300,
                    snap.swap_used_mb,
                    snap.swap_total_mb,
                    json.dumps(top, ensure_ascii=False),
                    duration_ms,
                ),
            )

    def sync_incidents(self, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
        """Upsert findings, close the ones that stopped.  Returns (new, closed_keys)."""
        now = time.time()
        live = {f.key for f in findings}
        with self._conn() as conn:
            rows = conn.execute("SELECT key, closed_at FROM incidents WHERE closed_at IS NULL").fetchall()
            known = {row["key"] for row in rows}
            closed = [row["key"] for row in rows if row["key"] not in live]
            for key in closed:
                conn.execute("UPDATE incidents SET closed_at=? WHERE key=?", (now, key))
            new: list[Finding] = []
            for finding in findings:
                if finding.key in known:
                    conn.execute(
                        "UPDATE incidents SET last_seen=?, body=?, value=?, severity=? WHERE key=?",
                        (now, finding.body, finding.value, finding.severity, finding.key),
                    )
                    continue
                previous = conn.execute(
                    "SELECT closed_at FROM incidents WHERE key=?", (finding.key,)
                ).fetchone()
                conn.execute(
                    "INSERT INTO incidents (key, kind, severity, title, body, hint, pid, value,"
                    " first_seen, last_seen, closed_at, acked_at, acked_by, escalated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)"
                    " ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen,"
                    " closed_at=NULL, acked_at=NULL, acked_by=NULL, escalated_at=NULL,"
                    " body=excluded.body, value=excluded.value, severity=excluded.severity",
                    (
                        finding.key,
                        finding.kind,
                        finding.severity,
                        finding.title,
                        finding.body,
                        finding.hint,
                        finding.pid,
                        finding.value,
                        now if not previous else previous["closed_at"] or now,
                        now,
                    ),
                )
                new.append(finding)
        return new, closed

    def record_actions(self, actions: list[Action]) -> None:
        if not actions:
            return
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO actions (ts, kind, target, detail, ok) VALUES (?,?,?,?,?)",
                [(a.ts, a.kind, a.target, a.detail, int(a.ok)) for a in actions],
            )

    def ack(self, key: str, who: str = "board") -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE incidents SET acked_at=?, acked_by=? WHERE key=? AND closed_at IS NULL",
                (time.time(), who, key),
            )
            return cur.rowcount > 0

    def mark_escalated(self, keys: list[str]) -> None:
        if not keys:
            return
        now = time.time()
        with self._conn() as conn:
            conn.executemany("UPDATE incidents SET escalated_at=? WHERE key=?", [(now, k) for k in keys])

    # --- reads ------------------------------------------------------------
    def recent_ticks(self, limit: int = 288) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ts, load1, cores, mem_used_mb, mem_total_mb, pressure, swap_used_mb,"
                " swap_total_mb, top_json, duration_ms FROM ticks ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def open_incidents(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE closed_at IS NULL ORDER BY severity DESC, first_seen DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_incidents(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_actions(self, limit: int = 30) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM actions ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def escalations_due(self, cfg: Config) -> list[dict]:
        if not cfg.escalation_enabled:
            return []
        now = time.time()
        placeholders = ",".join("?" for _ in cfg.escalate_severities) or "''"
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE closed_at IS NULL AND acked_at IS NULL"
                f" AND severity IN ({placeholders})"
                " AND (? - first_seen) >= ?"
                " AND (escalated_at IS NULL OR (? - escalated_at) >= ?)",
                (*cfg.escalate_severities, now, cfg.escalate_after_unacked_seconds, now, cfg.escalate_cooldown_seconds),
            ).fetchall()
        return [dict(row) for row in rows]