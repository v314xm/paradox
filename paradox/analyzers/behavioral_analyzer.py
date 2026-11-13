"""Поведенческий анализ как «второе мнение», а не источник находок.

Isolation Forest на нормализованных признаках сессий находит
статистические выбросы — сессии, непохожие на остальной трафик по
объёму, темпу, асимметрии или периодичности. Но выброс ≠ инцидент:
на чистом захвате тяжёлые хвосты и мультикаст дают такие же score, как
реальные аномалии на грязном (проверено калибровкой 2026-11-12).

Поэтому слой НЕ создаёт самостоятельных находок. Он аннотирует
существующие rule-находки: если сессия (или хост) уже попала в
`beaconing`/`large_transfer`/`rare_external_ip`/… И при этом является
статистическим выбросом — в evidence находки добавляются
`behavioral_score` и `behavioral_corroborated`. Это «второе мнение»,
усиливающее уже доказанное, а не новый шум.

Нормализация — log1p + robust-scale по медиане/IQR, НЕ Min-Max (тот
рвётся на одном крупном flow). Score — непрерывный `anomaly_scores`,
а не бинарный `predict` (в отличие от A-Detector, который теряет score).

Слой по умолчанию выключен (Config.behavioral_enabled=False).
"""
from __future__ import annotations

import math

from paradox.config import Config
from paradox.ml.isolation_forest import IsolationForest
from paradox.models import (
    CaptureState,
    Finding,
    make_session_key,
    packet_size_cv,
)
from paradox.net_utils import is_internal_ip

# Порядок колонок матрицы признаков. Каждая сессия (двунаправленный
# SessionKey) превращается в один вектор из этих значений.
_FEATURE_ORDER: tuple[str, ...] = (
    "packets",
    "bytes",
    "duration",
    "bytes_per_sec",
    "pkts_per_sec",
    "avg_pkt_size",
    "asym_ratio",
    "payload_cv",
    "gap_mean",
    "gap_cv",
    "port_hi",
    "port_lo",
    "is_tcp",
    "has_sni",
    "has_http_host",
    "has_dns",
)

# Счётные/масштабные признаки приводятся к log1p: один 100 МБ flow
# сожмёт линейную шкалу всем остальным. Бинарные признаки не трогаем.
_LOG_FEATURES: frozenset[str] = frozenset({
    "packets",
    "bytes",
    "duration",
    "bytes_per_sec",
    "pkts_per_sec",
    "avg_pkt_size",
    "asym_ratio",
    "payload_cv",
    "gap_mean",
    "port_hi",
    "port_lo",
})

# Host-level: профиль поведения внутреннего хоста. Все признаки —
# счётные/масштабные, поэтому log1p применяется ко всем.
_HOST_FEATURE_ORDER: tuple[str, ...] = (
    "unique_dst_ips",
    "unique_dst_ports",
    "total_flows",
    "total_bytes",
    "total_packets",
    "avg_bytes_per_flow",
    "unique_sni",
    "duration",
)


def _gap_stats(gap_sum: float, gap_sumsq: float, gap_count: int) -> tuple[float, float]:
    """(mean, cv) межпакетных интервалов из O(1)-сумм."""
    if gap_count <= 0:
        return 0.0, 0.0
    mean = gap_sum / gap_count
    variance = max(0.0, gap_sumsq / gap_count - mean * mean)
    cv = math.sqrt(variance) / mean if mean > 0 else 0.0
    return mean, cv


def _log1p_features(rows: list[dict[str, float]]) -> list[list[float]]:
    """Преобразовать словари признаков в матрицу чисел с log1p."""
    out = []
    for row in rows:
        out.append([
            math.log1p(row[name]) if name in _LOG_FEATURES else row[name]
            for name in _FEATURE_ORDER
        ])
    return out


def _robust_scale(X: list[list[float]]) -> list[list[float]]:
    """Центрирование медианой и масштабирование IQR по каждой колонке.

    В отличие от Min-Max не сжимается одним выбросом. Постоянная
    колонка (IQR = 0) превращается в нули — признак без разброса и
    не должен влиять на дерево.
    """
    if not X:
        return []
    n_rows = len(X)
    n_cols = len(X[0])
    out = [[0.0] * n_cols for _ in range(n_rows)]
    for c in range(n_cols):
        col = sorted(X[i][c] for i in range(n_rows))
        median = col[n_rows // 2]
        q1 = col[int(n_rows * 0.25)]
        q3 = col[int(n_rows * 0.75)]
        scale = (q3 - q1) or 1.0
        for i in range(n_rows):
            out[i][c] = (X[i][c] - median) / scale
    return out


def _scores_to_confidence(scores: list[float], contamination: float) -> list[float]:
    """Непрерывный anomaly-score → confidence [0, 1].

    Порог q — квантиль (1 - contamination): ниже него точки «нормальны».
    Выше — confidence растёт от 0.5 к 1.0 линейно до максимума. Так
    contamination задаёт форму, но не рубит оценку бинарно, как predict.
    """
    if not scores:
        return []
    ordered = sorted(scores)
    n = len(ordered)
    k = max(0, n - math.ceil(n * contamination))
    q = ordered[k] if k < n else ordered[-1]
    smax = ordered[-1]
    denom = (smax - q) or 1.0
    out = []
    for s in scores:
        conf = 0.5 + 0.5 * (s - q) / denom
        out.append(max(0.0, min(1.0, conf)))
    return out


class BehavioralAnalyzer:
    """Прогон Isolation Forest над сессиями захвата."""

    name = "behavioral_anomaly"

    def score_sessions(self, state: CaptureState, config: Config) -> list[dict]:
        """Аномальные сессии по убыванию score.

        Возвращает НЕ находки, а список словарей — «второе мнение»,
        которое corroborate() накладывает на rule-находки. Словарь:
        src_ip/dst_ip/dst_port (internal → external), score, confidence,
        rank, stats (packets/bytes/duration_sec/out_in_ratio/gap_cv).
        """
        if not config.behavioral_enabled:
            return []
        if len(state.flows) < config.behavioral_min_flows:
            return []

        sessions = self._build_sessions(state, config)
        if len(sessions) < config.behavioral_min_flows:
            return []

        X = _log1p_features([s["features"] for s in sessions])
        Xn = _robust_scale(X)

        forest = IsolationForest(seed=config.behavioral_seed)
        forest.fit(Xn)
        scores = forest.anomaly_scores(Xn)
        confidences = _scores_to_confidence(
            scores, config.behavioral_contamination,
        )

        out: list[dict] = []
        ranked = sorted(range(len(sessions)), key=lambda i: -scores[i])
        for rank, idx in enumerate(ranked, start=1):
            conf = confidences[idx]
            # ranked отсортирован по убыванию score, а confidence
            # монотонна по score — дальше только ниже порога.
            if conf < config.behavioral_confidence_min:
                break
            if len(out) >= config.behavioral_max_findings:
                break
            s = sessions[idx]
            out.append({
                "src_ip": s["src_ip"],
                "dst_ip": s["dst_ip"],
                "dst_port": s["dst_port"],
                "score": scores[idx],
                "confidence": conf,
                "rank": rank,
                "stats": s["stats"],
            })
        return out

    # ------------------------------------------------------------------
    # host-level
    # ------------------------------------------------------------------

    def score_hosts(self, state: CaptureState, config: Config) -> list[Finding]:
        """Хосты с аномальным поведенческим профилем (standalone).

        Единственное место, где ML-слой создаёт находки: на уровне хоста
        выброс осмысленнее, чем на уровне одной сессии. Признаки — число
        разных адресатов/портов, объём и темп исходящего трафика.
        """
        if not config.behavioral_enabled:
            return []
        hosts = self._build_hosts(state, config)
        if len(hosts) < config.behavioral_min_hosts:
            return []

        X = [
            [math.log1p(row["features"][name]) for name in _HOST_FEATURE_ORDER]
            for row in hosts
        ]
        Xn = _robust_scale(X)

        forest = IsolationForest(seed=config.behavioral_seed)
        forest.fit(Xn)
        scores = forest.anomaly_scores(Xn)
        confidences = _scores_to_confidence(
            scores, config.behavioral_contamination,
        )

        findings: list[Finding] = []
        ranked = sorted(range(len(hosts)), key=lambda i: -scores[i])
        for rank, idx in enumerate(ranked, start=1):
            conf = confidences[idx]
            if conf < config.behavioral_confidence_min:
                break
            if len(findings) >= config.behavioral_max_findings:
                break
            h = hosts[idx]
            stats = h["stats"]
            findings.append(Finding(
                type="host_behavior_anomaly",
                value=h["ip"],
                confidence=round(conf, 3),
                src_ip=h["ip"],
                evidence={
                    "src_ip": h["ip"],
                    "anomaly_score": round(scores[idx], 4),
                    "rank": rank,
                    "unique_dst_ips": stats["unique_dst_ips"],
                    "unique_dst_ports": stats["unique_dst_ports"],
                    "total_flows": stats["total_flows"],
                    "total_bytes": stats["total_bytes"],
                    "total_packets": stats["total_packets"],
                    "avg_bytes_per_flow": stats["avg_bytes_per_flow"],
                    "unique_sni": stats["unique_sni"],
                    "duration_sec": stats["duration_sec"],
                },
                first_seen=h["first_ts"],
                last_seen=h["last_ts"],
            ))
        return findings

    def _build_hosts(self, state: CaptureState, config: Config) -> list[dict]:
        """Профили внутренних хостов: счётчики по state.flows."""
        hosts: dict[str, dict] = {}
        for key, flow in state.flows.items():
            src = key.src_ip
            if not is_internal_ip(src, config):
                continue
            h = hosts.get(src)
            if h is None:
                h = {
                    "ip": src,
                    "dst_ips": set(),
                    "dst_ports": set(),
                    "snis": set(),
                    "flows": 0,
                    "bytes": 0,
                    "packets": 0,
                    "first_ts": None,
                    "last_ts": None,
                }
                hosts[src] = h
            h["dst_ips"].add(key.dst_ip)
            if key.dst_port is not None:
                h["dst_ports"].add(key.dst_port)
            if flow.sni:
                h["snis"].add(flow.sni.lower())
            h["flows"] += 1
            h["bytes"] += flow.bytes_sent
            h["packets"] += flow.packets
            if flow.first_ts is not None:
                if h["first_ts"] is None or flow.first_ts < h["first_ts"]:
                    h["first_ts"] = flow.first_ts
            if flow.last_ts is not None:
                if h["last_ts"] is None or flow.last_ts > h["last_ts"]:
                    h["last_ts"] = flow.last_ts

        out = []
        for h in hosts.values():
            flows = h["flows"]
            duration = max(
                0.0, (h["last_ts"] or 0.0) - (h["first_ts"] or 0.0),
            )
            out.append({
                "ip": h["ip"],
                "first_ts": h["first_ts"],
                "last_ts": h["last_ts"],
                "features": {
                    "unique_dst_ips": float(len(h["dst_ips"])),
                    "unique_dst_ports": float(len(h["dst_ports"])),
                    "total_flows": float(flows),
                    "total_bytes": float(h["bytes"]),
                    "total_packets": float(h["packets"]),
                    "avg_bytes_per_flow": (
                        (h["bytes"] / flows) if flows else 0.0
                    ),
                    "unique_sni": float(len(h["snis"])),
                    "duration": duration,
                },
                "stats": {
                    "unique_dst_ips": len(h["dst_ips"]),
                    "unique_dst_ports": len(h["dst_ports"]),
                    "total_flows": flows,
                    "total_bytes": h["bytes"],
                    "total_packets": h["packets"],
                    "avg_bytes_per_flow": round(
                        (h["bytes"] / flows), 1,
                    ) if flows else 0,
                    "unique_sni": len(h["snis"]),
                    "duration_sec": round(duration, 1),
                },
            })
        return out

    # ------------------------------------------------------------------
    # feature extraction
    # ------------------------------------------------------------------

    def _build_sessions(self, state: CaptureState, config: Config) -> list[dict]:
        """Свернуть направленные flow в двунаправленные сессии."""
        sessions: dict = {}
        for key, flow in state.flows.items():
            sk = make_session_key(key)
            s = sessions.get(sk)
            if s is None:
                s = {
                    "ip_lo": sk.ip_lo, "port_lo": sk.port_lo,
                    "ip_hi": sk.ip_hi, "port_hi": sk.port_hi,
                    "proto": sk.proto,
                    "packets": 0, "bytes": 0, "bytes_sumsq": 0,
                    "first_ts": None, "last_ts": None,
                    "gap_sum": 0.0, "gap_sumsq": 0.0, "gap_count": 0,
                    "has_sni": False, "has_http_host": False,
                    "endpoint_bytes": {},
                }
                sessions[sk] = s

            s["packets"] += flow.packets
            s["bytes"] += flow.bytes_sent
            s["bytes_sumsq"] += flow.bytes_sumsq
            s["gap_sum"] += flow.gap_sum
            s["gap_sumsq"] += flow.gap_sumsq
            s["gap_count"] += flow.gap_count
            if flow.first_ts is not None:
                if s["first_ts"] is None or flow.first_ts < s["first_ts"]:
                    s["first_ts"] = flow.first_ts
            if flow.last_ts is not None:
                if s["last_ts"] is None or flow.last_ts > s["last_ts"]:
                    s["last_ts"] = flow.last_ts
            if flow.sni:
                s["has_sni"] = True
            if flow.http_host:
                s["has_http_host"] = True
            ep = (key.src_ip, key.src_port or 0)
            s["endpoint_bytes"][ep] = s["endpoint_bytes"].get(ep, 0) + flow.bytes_sent

        # SNI из session_sni (обратный поток может не видеть ClientHello).
        for sk, sni in state.session_sni.items():
            s = sessions.get(sk)
            if s is not None and sni:
                s["has_sni"] = True

        out = []
        for s in sessions.values():
            features = self._features(s, state)
            src_ip, src_port, dst_ip, dst_port = _orient(s, config)
            out.append({
                "src_ip": src_ip, "src_port": src_port,
                "dst_ip": dst_ip, "dst_port": dst_port,
                "proto": s["proto"],
                "first_ts": s["first_ts"], "last_ts": s["last_ts"],
                "features": features,
                "stats": {
                    "packets": s["packets"],
                    "bytes": s["bytes"],
                    "duration_sec": round(
                        max(0.0, (s["last_ts"] or 0.0) - (s["first_ts"] or 0.0)),
                        1,
                    ),
                    "out_in_ratio": round(features["asym_ratio"], 2),
                    "gap_cv": round(features["gap_cv"], 3),
                    "avg_pkt_size": round(features["avg_pkt_size"], 1),
                },
            })
        return out

    def _features(self, s: dict, state: CaptureState) -> dict[str, float]:
        packets = s["packets"]
        total_bytes = s["bytes"]
        duration = max(0.0, (s["last_ts"] or 0.0) - (s["first_ts"] or 0.0))

        bytes_per_sec = total_bytes / duration if duration > 0 else 0.0
        pkts_per_sec = packets / duration if duration > 0 else 0.0
        avg_pkt_size = (total_bytes / packets) if packets else 0.0

        # Асимметрия: max/min байт по конечным точкам сессии.
        ep_bytes = list(s["endpoint_bytes"].values())
        max_ep = max(ep_bytes) if ep_bytes else 0.0
        min_ep = min(ep_bytes) if ep_bytes else 0.0
        asym_ratio = max_ep / min_ep if min_ep > 0 else max_ep

        payload_cv = packet_size_cv(packets, total_bytes, s["bytes_sumsq"])
        gap_mean, gap_cv = _gap_stats(s["gap_sum"], s["gap_sumsq"], s["gap_count"])

        has_dns = (
            s["ip_lo"] in state.dns_answers_by_ip
            or s["ip_hi"] in state.dns_answers_by_ip
        )

        return {
            "packets": float(packets),
            "bytes": float(total_bytes),
            "duration": duration,
            "bytes_per_sec": bytes_per_sec,
            "pkts_per_sec": pkts_per_sec,
            "avg_pkt_size": avg_pkt_size,
            "asym_ratio": asym_ratio,
            "payload_cv": payload_cv,
            "gap_mean": gap_mean,
            "gap_cv": gap_cv,
            "port_hi": float(s["port_hi"] or 0),
            "port_lo": float(s["port_lo"] or 0),
            "is_tcp": 1.0 if s["proto"] == "tcp" else 0.0,
            "has_sni": 1.0 if s["has_sni"] else 0.0,
            "has_http_host": 1.0 if s["has_http_host"] else 0.0,
            "has_dns": 1.0 if has_dns else 0.0,
        }


def corroborate(
    findings: list[Finding],
    state: CaptureState,
    config: Config,
) -> None:
    """Аннотировать rule-находки поведенческим выбросом (второе мнение).

    Для каждой находки, чья пара (src_ip, dst_ip) — или src_ip как хост —
    попала в топ статистических выбросов, в evidence добавляются
    behavioral_score и behavioral_corroborated. Новые находки НЕ создаются:
    статистика только усиливает уже доказанное правило.
    """
    if not config.behavioral_enabled:
        return

    sessions = BehavioralAnalyzer().score_sessions(state, config)
    if not sessions:
        return

    pair_scores: dict[tuple[str, str], float] = {}
    host_scores: dict[str, float] = {}
    for s in sessions:
        pair = (s["src_ip"], s["dst_ip"])
        pair_scores[pair] = max(pair_scores.get(pair, 0.0), s["score"])
        host_scores[s["src_ip"]] = max(
            host_scores.get(s["src_ip"], 0.0), s["score"],
        )

    for f in findings:
        score: float | None = None
        if f.src_ip and f.dst_ip:
            # Точное совпадение пары (в обе стороны). Host-fallback НЕ
            # применяем: иначе на захвате с парой хостов «усилились» бы
            # все находки на активном хосте, а не конкретная сессия.
            score = pair_scores.get((f.src_ip, f.dst_ip))
            if score is None:
                score = pair_scores.get((f.dst_ip, f.src_ip))
        elif f.src_ip:
            # Доменные находки (typosquatting, dga_domain) без dst_ip —
            # матчим по хосту-источнику.
            score = host_scores.get(f.src_ip)

        if score is not None:
            f.evidence["behavioral_score"] = round(score, 3)
            f.evidence["behavioral_corroborated"] = True


def _orient(s: dict, config: Config) -> tuple[str, int | None, str, int | None]:
    """Представить сессию как internal → external, где это возможно.

    Если оба конца одной природы — оставляем канонический порядок
    (ip_lo → ip_hi) из SessionKey.
    """
    lo_internal = is_internal_ip(s["ip_lo"], config)
    hi_internal = is_internal_ip(s["ip_hi"], config)
    if lo_internal and not hi_internal:
        return s["ip_lo"], s["port_lo"], s["ip_hi"], s["port_hi"]
    if hi_internal and not lo_internal:
        return s["ip_hi"], s["port_hi"], s["ip_lo"], s["port_lo"]
    return s["ip_lo"], s["port_lo"], s["ip_hi"], s["port_hi"]
