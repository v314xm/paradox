"""
Token bucket для rate limit.

У VT free tier: 4 запроса в минуту. У AbuseIPDB: 1000 в день.
Используем простой token bucket — единственный класс на все
лимиты. Проверка перед каждым запросом, без блокировки.
"""
import time


class TokenBucket:
    """
    Token bucket: N токенов, восполнение M токенов в секунду.

    Пример:
      bucket = TokenBucket(capacity=4, refill_per_sec=4/60)
      # 4 запроса разом, потом по одному каждые 15 секунд
    """

    def __init__(self, capacity: int, refill_per_sec: float):
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_per_sec <= 0:
            raise ValueError("refill_per_sec must be > 0")
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self.capacity,
            self._tokens + elapsed * self.refill_per_sec,
        )
        self._last_refill = now

    def try_acquire(self) -> bool:
        """Попробовать взять токен. Не блокирует."""
        self._refill()
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False
