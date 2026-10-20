"""
Тесты EnrichmentCache и TokenBucket.

Без сети, без провайдеров — только инфраструктура.
"""
import time
from pathlib import Path

import pytest

from paradox.integrations.base import EnrichmentResult
from paradox.integrations.cache import EnrichmentCache
from paradox.integrations.rate_limit import TokenBucket


def test_cache_put_get(tmp_path):
    """Базовый round-trip."""
    db = tmp_path / "enrichment.db"
    with EnrichmentCache(db) as cache:
        result = EnrichmentResult(
            source="shodan_internetdb",
            ioc="8.8.8.8",
            data={"ports": [53, 443], "hostnames": ["dns.google"]},
            fetched_at=time.time(),
            ttl_days=7,
        )
        cache.put(result)

        got = cache.get("shodan_internetdb", "8.8.8.8")
        assert got is not None
        assert got.source == "shodan_internetdb"
        assert got.ioc == "8.8.8.8"
        assert got.data["ports"] == [53, 443]


def test_cache_get_missing(tmp_path):
    """Нет записи — None."""
    db = tmp_path / "enrichment.db"
    with EnrichmentCache(db) as cache:
        assert cache.get("shodan_internetdb", "1.2.3.4") is None


def test_cache_get_stale(tmp_path):
    """Запись устарела — None."""
    db = tmp_path / "enrichment.db"
    with EnrichmentCache(db) as cache:
        old = EnrichmentResult(
            source="shodan_internetdb",
            ioc="8.8.8.8",
            data={"ports": [53]},
            fetched_at=time.time() - 10 * 86400,  # 10 дней назад
            ttl_days=7,
        )
        cache.put(old)

        assert cache.get("shodan_internetdb", "8.8.8.8") is None


def test_cache_put_overwrites(tmp_path):
    """UPSERT: повторный put меняет данные."""
    db = tmp_path / "enrichment.db"
    with EnrichmentCache(db) as cache:
        cache.put(EnrichmentResult(
            source="shodan_internetdb", ioc="8.8.8.8",
            data={"ports": [53]}, fetched_at=time.time(), ttl_days=7,
        ))
        cache.put(EnrichmentResult(
            source="shodan_internetdb", ioc="8.8.8.8",
            data={"ports": [53, 443]}, fetched_at=time.time(), ttl_days=7,
        ))

        got = cache.get("shodan_internetdb", "8.8.8.8")
        assert got.data["ports"] == [53, 443]


def test_cache_invalidate_old(tmp_path):
    """Очистка старых записей."""
    db = tmp_path / "enrichment.db"
    with EnrichmentCache(db) as cache:
        cache.put(EnrichmentResult(
            source="x", ioc="old",
            data={}, fetched_at=time.time() - 40 * 86400, ttl_days=7,
        ))
        cache.put(EnrichmentResult(
            source="x", ioc="new",
            data={}, fetched_at=time.time(), ttl_days=7,
        ))

        deleted = cache.invalidate_old(older_than_days=30)
        assert deleted == 1
        assert cache.get("x", "new") is not None


def test_cache_stats(tmp_path):
    """Сводка: total, stale, by_source."""
    db = tmp_path / "enrichment.db"
    with EnrichmentCache(db) as cache:
        cache.put(EnrichmentResult(
            source="shodan", ioc="1.1.1.1",
            data={}, fetched_at=time.time(), ttl_days=7,
        ))
        cache.put(EnrichmentResult(
            source="shodan", ioc="8.8.8.8",
            data={}, fetched_at=time.time() - 10 * 86400, ttl_days=7,
        ))
        cache.put(EnrichmentResult(
            source="vt", ioc="9.9.9.9",
            data={}, fetched_at=time.time(), ttl_days=7,
        ))

        stats = cache.stats()
        assert stats["total"] == 3
        assert stats["stale"] == 1
        assert stats["by_source"]["shodan"] == 2
        assert stats["by_source"]["vt"] == 1


def test_token_bucket_immediate():
    """Достаточно токенов — сразу True."""
    bucket = TokenBucket(capacity=5, refill_per_sec=1.0)
    for _ in range(5):
        assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False


def test_token_bucket_refills():
    """Токены восполняются."""
    bucket = TokenBucket(capacity=1, refill_per_sec=100.0)
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False
    time.sleep(0.05)  # 5 токенов должно восполниться (но capped на 1)
    assert bucket.try_acquire() is True


def test_token_bucket_invalid():
    """Валидация параметров."""
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_per_sec=1.0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_per_sec=0)