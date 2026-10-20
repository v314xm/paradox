"""SQLite-хранилище истории прогонов.

Файл: %APPDATA%\\Paradox\\history.db (Windows),
      ~/.local/share/Paradox/history.db (POSIX fallback).

Схема v1:
    runs(id, ts, pcap_path, pcap_sha256,
         findings, contradictions, enriched, report_json)

report_json — полный отчёт из run_pipeline, as-is. Обогащение
мутирует его in-place, поэтому refresh_current делает UPDATE.

Если БД недоступна — все методы становятся no-op, история
работает in-memory как раньше. GUI не падает.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path


def _db_dir() -> Path:
    base = os.getenv("APPDATA")
    if not base:
        base = os.getenv("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "Paradox"


class HistoryDB:
    def __init__(self, path: Path | None = None) -> None:
        self._ok = False
        try:
            if path is None:
                d = _db_dir()
                d.mkdir(parents=True, exist_ok=True)
                path = d / "history.db"
            self._path = path
            self._init_schema()
            self._ok = True
        except Exception:
            self._ok = False
            self._path = path or Path(":memory:")

    def _conn(self):
        return sqlite3.connect(str(self._path))

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS runs ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " ts TEXT NOT NULL,"
                " pcap_path TEXT,"
                " pcap_sha256 TEXT,"
                " findings INTEGER DEFAULT 0,"
                " contradictions INTEGER DEFAULT 0,"
                " enriched INTEGER DEFAULT 0,"
                " report_json TEXT NOT NULL"
                ")"
            )
            c.execute("CREATE INDEX IF NOT EXISTS ix_runs_id ON runs(id DESC)")

    def insert(self, report: dict) -> int | None:
        if not self._ok:
            return None
        try:
            prov = report.get("provenance") or {}
            s = report.get("summary") or {}
            ts = datetime.now().isoformat(timespec="seconds")
            payload = json.dumps(report, ensure_ascii=False, sort_keys=True)
            with self._conn() as c:
                cur = c.execute(
                    "INSERT INTO runs (ts, pcap_path, pcap_sha256, findings,"
                    " contradictions, enriched, report_json)"
                    " VALUES (?, ?, ?, ?, ?, 0, ?)",
                    (ts,
                     prov.get("pcap_path", "") or "",
                     prov.get("pcap_sha256", "") or "",
                     int(s.get("findings", 0) or 0),
                     int(s.get("contradictions", 0) or 0),
                     payload),
                )
                return int(cur.lastrowid)
        except Exception:
            return None

    def update_report(self, run_id: int, report: dict, enriched: bool) -> None:
        if not self._ok or run_id is None:
            return
        try:
            payload = json.dumps(report, ensure_ascii=False, sort_keys=True)
            with self._conn() as c:
                c.execute(
                    "UPDATE runs SET report_json=?, enriched=? WHERE id=?",
                    (payload, 1 if enriched else 0, int(run_id)),
                )
        except Exception:
            pass

    def load_recent(self, limit: int = 20) -> list[tuple[int, datetime, dict]]:
        if not self._ok:
            return []
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT id, ts, report_json FROM runs"
                    " ORDER BY id DESC LIMIT ?", (int(limit),),
                ).fetchall()
        except Exception:
            return []
        out: list[tuple[int, datetime, dict]] = []
        for run_id, ts_s, payload in rows:
            try:
                ts = datetime.fromisoformat(ts_s)
            except ValueError:
                ts = datetime.now()
            try:
                report = json.loads(payload)
            except (TypeError, ValueError):
                continue
            out.append((int(run_id), ts, report))
        return out

    def clear(self) -> None:
        if not self._ok:
            return
        try:
            with self._conn() as c:
                c.execute("DELETE FROM runs")
        except Exception:
            pass
