"""
SQLite-кэш результатов обогащения.

Зачем:
- Rate limits (VT: 4 req/min) — не должны заново запрашивать то,
  что уже спрашивали недавно.
- Экономия: один IP в 50 findings → 1 запрос, а не 50.
- Offline работа: без сети можно посмотреть прошлые результаты.

Схема:
    enrichment (
        source TEXT,      -- "shodan_internetdb"
        ioc TEXT,         -- "8.8.8.8"
        data_json TEXT,   -- JSON сырого ответа
        fetched_at REAL,  -- unix timestamp
        ttl_days INTEGER,
        PRIMARY KEY (source, ioc)
    )

Метод get() возвращает None если запись устарела или отсутствует.
Метод put() перезаписывает запись (UPSERT).
"""
import json
import sqlite3
import time
from pathlib import Path

from pcap_triage.integrations.base import EnrichmentResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment (
    source TEXT NOT NULL,
    ioc TEXT NOT NULL,
    data_json TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    ttl_days INTEGER NOT NULL,
    PRIMARY KEY (source, ioc)
);
CREATE INDEX IF NOT EXISTS idx_fetched_at ON enrichment(fetched_at);
"""


class EnrichmentCache:
    """
    SQLite-кэш результатов обогащения.

    Один файл на весь инструмент: reports/.cache/enrichment.db.
    Создаётся автоматически.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def get(self, source: str, ioc: str) -> EnrichmentResult | None:
        """
        Вернуть закэшированный результат, если он свежий.
        None — если записи нет или она устарела.
        """
        cur = self._conn.execute(
            "SELECT data_json, fetched_at, ttl_days "
            "FROM enrichment WHERE source = ? AND ioc = ?",
            (source, ioc),
        )
        row = cur.fetchone()
        if row is None:
            return None

        data_json, fetched_at, ttl_days = row
        age_days = (time.time() - fetched_at) / 86400
        if age_days > ttl_days:
            return None  # устарело

        try:
            data = json.loads(data_json)
        except (json.JSONDecodeError, TypeError):
            return None

        return EnrichmentResult(
            source=source,
            ioc=ioc,
            data=data,
            fetched_at=fetched_at,
            ttl_days=ttl_days,
        )

    def put(self, result: EnrichmentResult) -> None:
        """Сохранить результат (UPSERT)."""
        self._conn.execute(
            "INSERT INTO enrichment (source, ioc, data_json, fetched_at, ttl_days) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(source, ioc) DO UPDATE SET "
            "  data_json = excluded.data_json, "
            "  fetched_at = excluded.fetched_at, "
            "  ttl_days = excluded.ttl_days",
            (
                result.source,
                result.ioc,
                json.dumps(result.data, ensure_ascii=False, sort_keys=True),
                result.fetched_at,
                result.ttl_days,
            ),
        )
        self._conn.commit()

    def invalidate_old(self, older_than_days: int = 30) -> int:
        """Удалить записи старше N дней. Вернуть количество удалённых."""
        cutoff = time.time() - older_than_days * 86400
        cur = self._conn.execute(
            "DELETE FROM enrichment WHERE fetched_at < ?",
            (cutoff,),
        )
        self._conn.commit()
        return cur.rowcount

    def clear(self) -> int:
        """Очистить весь кэш. Вернуть количество удалённых."""
        cur = self._conn.execute("DELETE FROM enrichment")
        self._conn.commit()
        return cur.rowcount

    def stats(self) -> dict:
        """Сколько записей всего, сколько устарело."""
        total = self._conn.execute(
            "SELECT COUNT(*) FROM enrichment"
        ).fetchone()[0]

        now = time.time()
        stale = self._conn.execute(
            "SELECT COUNT(*) FROM enrichment "
            "WHERE (? - fetched_at) / 86400 > ttl_days",
            (now,),
        ).fetchone()[0]

        by_source = dict(self._conn.execute(
            "SELECT source, COUNT(*) FROM enrichment GROUP BY source"
        ).fetchall())

        return {
            "total": total,
            "stale": stale,
            "by_source": by_source,
        }