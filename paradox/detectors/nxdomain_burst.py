from bisect import bisect_left, bisect_right

from paradox.config import Config
from paradox.models import CaptureState, Finding

# v0.9.0: nxdomain_burst windowing


def _max_in_window(ts_sorted: list[float], window_sec: int) -> int:
    """
    Максимум точек в скользящем окне window_sec секунд.

    ts_sorted — отсортированный по возрастанию список unix-ts.
    O(n), два указателя: расширяем right, сдвигаем left, пока
    разница ts[right] - ts[left] не влезет в окно.
    """
    return _best_window(ts_sorted, window_sec)[1]


def _best_window(ts_sorted: list[float], window_sec: int) -> tuple[float, int]:
    """Начало и размер самого плотного окна (тот же two-pointer)."""
    if not ts_sorted:
        return 0.0, 0
    left = 0
    best_start = ts_sorted[0]
    best = 1
    for right in range(len(ts_sorted)):
        while ts_sorted[right] - ts_sorted[left] > window_sec:
            left += 1
        if right - left + 1 > best:
            best = right - left + 1
            best_start = ts_sorted[left]
    return best_start, best


def _count_in_window(
    ts_sorted: list[float], start: float, window_sec: int,
) -> int:
    """Сколько точек попадает в [start, start + window_sec]."""
    return bisect_right(ts_sorted, start + window_sec) - bisect_left(
        ts_sorted, start,
    )


class NXDOMAINBurstDetector:
    """
    Один хост получил >= N NXDOMAIN за окно W секунд.

    v0.9.0: скользящее окно вместо total count за файл.

    Раньше (0.7.0–0.8.0) считали за весь файл — на FIN-2015
    давало 93 findings из 316 (29%). Большинство — размазанные
    по часу опечатки в браузерах и NXDOMAIN-ы от легитимных
    сервисов.

    Backward compat: если для src нет timestamps (старые тесты,
    ручной state), падаем на total count и помечаем
    evidence windowed=False.
    """
    name = "nxdomain_burst"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        threshold = config.nxdomain_burst_threshold
        window = config.nxdomain_burst_window_sec
        min_ratio = config.nxdomain_burst_min_ratio

        for src_ip, total in state.dns_nxdomain_by_src.items():
            if total == 0:
                continue

            ts_list = state.dns_nxdomain_ts_by_src.get(src_ip)
            if ts_list:
                ts_sorted = sorted(ts_list)
                burst_start, max_win = _best_window(ts_sorted, window)
                windowed = True
                signal = max_win
            else:
                burst_start = None
                max_win = total
                windowed = False
                signal = total

            if signal < threshold:
                continue

            # ratio-фильтр. Знаменатель — DNS-запросы в ТОМ ЖЕ окне,
            # что и всплеск NXDOMAIN. Раньше делили на total за весь
            # захват: при 6 NXDOMAIN в минуту и 100 запросах за час
            # ratio=0.057 < порога, т.е. «5 в минуту» фактически
            # превращался в десятки.
            all_q = state.dns_queries_by_src.get(src_ip)
            total_dns = sum(all_q.values()) if all_q else signal

            query_ts = state.dns_query_ts_by_src.get(src_ip) or []
            dns_in_window: int | None = None
            if query_ts and windowed and burst_start is not None:
                # Окно всплеска NXDOMAIN, а не самое шумное окно
                # запросов: иначе шумный браузерный час в другом
                # месте захвата глушит реальный всплеск.
                dns_in_window = _count_in_window(
                    sorted(query_ts), burst_start, window,
                )

            if dns_in_window is not None and windowed:
                ratio = signal / dns_in_window if dns_in_window > 0 else 1.0
            else:
                # Backward compat: нет ts запросов — падаем на total.
                ratio = signal / total_dns if total_dns > 0 else 1.0

            if ratio < min_ratio:
                continue

            confidence = round(min(0.9, 0.4 + signal * 0.05), 3)

            # timestamps для timeline
            first_seen: float | None = None
            last_seen: float | None = None
            if ts_list:
                first_seen = min(ts_list)
                last_seen = max(ts_list)

            findings.append(Finding(
                type="nxdomain_burst",
                value=src_ip,
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "nxdomain_count": total,
                    "max_in_window": max_win,
                    "window_sec": window,
                    "threshold": threshold,
                    "windowed": windowed,
                    "ratio": round(ratio, 3),
                    "total_dns_queries": total_dns,
                    "dns_in_window": dns_in_window,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            ))

        return findings
