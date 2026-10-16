from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding

# v0.9.0: nxdomain_burst windowing


def _max_in_window(ts_sorted: list[float], window_sec: int) -> int:
    """
    Максимум точек в скользящем окне window_sec секунд.

    ts_sorted — отсортированный по возрастанию список unix-ts.
    O(n), два указателя: расширяем right, сдвигаем left, пока
    разница ts[right] - ts[left] не влезет в окно.
    """
    if not ts_sorted:
        return 0
    left = 0
    best = 1
    for right in range(len(ts_sorted)):
        while ts_sorted[right] - ts_sorted[left] > window_sec:
            left += 1
        best = max(best, right - left + 1)
    return best


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

        for src_ip, total in state.dns_nxdomain_by_src.items():
            if total == 0:
                continue

            ts_list = state.dns_nxdomain_ts_by_src.get(src_ip)
            if ts_list:
                ts_sorted = sorted(ts_list)
                max_win = _max_in_window(ts_sorted, window)
                windowed = True
                signal = max_win
            else:
                max_win = total
                windowed = False
                signal = total

            if signal < threshold:
                continue

            confidence = round(min(0.9, 0.4 + signal * 0.05), 3)

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
                },
            ))

        return findings
