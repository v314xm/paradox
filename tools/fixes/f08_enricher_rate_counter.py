"""f08: enricher — errors_rate_limited counter.

Раньше: при ответе провайдера 429 инкрементился stats["errors"], но
_classify_error() не увеличивал ни одной категории (был `pass`).
Итог: errors_network + errors_auth + errors_server < errors. В GUI
видно «Ошибок: 5, сетевых: 2, auth: 1» — не сходится.

Фикс: добавляем errors_rate_limited. Сумма категорий = errors.
Локальный token bucket (stats["rate_limited"]) считается отдельно.
"""
from pathlib import Path

from tools._patcher import assert_applied, patch

NAME = "f08: enricher.py — errors_rate_limited"
FILES = ["paradox/integrations/enricher.py"]

_OLD_INIT = '''            # errors разбит по категориям — сетевые / авторизация /
            # сервер 5xx. Сумма = общее число ошибок.
            "errors": 0,
            "errors_network": 0,
            "errors_auth": 0,
            "errors_server": 0,'''

_NEW_INIT = '''            # errors разбит по категориям — сетевые / авторизация /
            # сервер 5xx / провайдер вернул 429. Сумма = общее число
            # ошибок (errors). rate_limited (локальный token bucket)
            # считается отдельно и в errors НЕ входит.
            "errors": 0,
            "errors_network": 0,
            "errors_auth": 0,
            "errors_server": 0,
            "errors_rate_limited": 0,'''

_OLD_CLASSIFY = '''    def _classify_error(self, error: str) -> None:
        """Разложить ошибку по категориям для статистики."""
        e = error.lower()
        if ("401" in e or "403" in e or "unauthorized" in e
                or "forbidden" in e or "key" in e and "not set" in e):
            self.stats["errors_auth"] += 1
        elif "429" in e or "rate limited" in e:
            # Уже посчитано в rate_limited; не дублируем.
            pass
        elif ("500" in e or "502" in e or "503" in e or "504" in e
              or "server error" in e):
            self.stats["errors_server"] += 1
        else:
            self.stats["errors_network"] += 1'''

_NEW_CLASSIFY = '''    def _classify_error(self, error: str) -> None:
        """Разложить ошибку по категориям.

        Инвариант: errors_auth + errors_network + errors_server +
        errors_rate_limited == errors. Локальный rate_limited
        (наш token bucket) в errors НЕ входит — считается отдельно.
        """
        e = error.lower()
        if ("401" in e or "403" in e or "unauthorized" in e
                or "forbidden" in e or "key" in e and "not set" in e):
            self.stats["errors_auth"] += 1
        elif "429" in e or "rate limited" in e:
            # Провайдер вернул 429 — его rate limit, не наш.
            self.stats["errors_rate_limited"] += 1
        elif ("500" in e or "502" in e or "503" in e or "504" in e
              or "server error" in e):
            self.stats["errors_server"] += 1
        else:
            self.stats["errors_network"] += 1'''


def apply(root: Path) -> bool:
    changed = False
    changed |= patch(root, FILES[0], _OLD_INIT, _NEW_INIT)
    changed |= patch(root, FILES[0], _OLD_CLASSIFY, _NEW_CLASSIFY)
    return changed


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], '"errors_rate_limited": 0,')
    assert_applied(root, FILES[0], 'self.stats["errors_rate_limited"] += 1')
