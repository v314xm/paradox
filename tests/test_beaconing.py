"""
Тесты BeaconingDetector.

Проверяем:
- периодические соединения → finding
- нерегулярные → нет
- мало соединений → нет
- большие соединения → нет (это не heartbeat, а загрузка)
- allowlist SNI/Host (CDN/analytics)
- payload variance (const vs random)
- rate check (burst vs beacon)
- skip internal dst
- multi-tenant filter (0.7.0)
- mail-port filter (0.7.0)

Плюс регрессии на будущее — если что-то поедет в алгоритме.
"""
from pcap_triage.config import Config
from pcap_triage.detectors.beaconing import BeaconingDetector
from pcap_triage.models import CaptureState, FlowKey, FlowStats


def _beacon_state(
    flows,
    sni=None,
    http_host=None,
    sni_list=None,
    host_list=None,
):
    """
    flows: list of (src, dst, dport, sport, first_ts, packets, bytes).

    sni / http_host — проставить всем flow одно значение.
    sni_list / host_list — по индексу flow (циклически).
    Приоритет: list > single.
    """
    state = CaptureState()
    for i, (src, dst, dport, sport, ts, pkts, byts) in enumerate(flows):
        key = FlowKey(
            proto="tcp", src_ip=src, dst_ip=dst,
            src_port=sport, dst_port=dport,
        )
        fs = FlowStats(packets=pkts, bytes_sent=byts)
        fs.first_ts = ts
        fs.last_ts = ts + 1.0
        if sni_list is not None:
            fs.sni = sni_list[i % len(sni_list)]
        elif sni is not None:
            fs.sni = sni
        if host_list is not None:
            fs.http_host = host_list[i % len(host_list)]
        elif http_host is not None:
            fs.http_host = http_host
        state.flows[key] = fs
    return state


def _regular_flows(
    n=25,
    interval=60.0,
    jitter_offset=0.0,
    src="192.168.1.100",
    dst="203.0.113.5",
    dport=443,
    sport_base=50000,
    pkts=5,
    byts=500,
):
    """
    N flows с интервалом `interval` и опциональным +/- `jitter_offset`.

    Математика jitter (важно для выбора значений):
      jitter_offset | intervals | pstdev | jitter ≈
      --------------|-----------|--------|----------
             0      | 60, 60    |   0    |   0
            ±1      | 58, 62    |   2    |   0.033
            ±2      | 56, 64    |   4    |   0.067
            ±3      | 54, 66    |   6    |   0.100  ← граница
            ±4      | 52, 68    |   8    |   0.133  ← режется
    """
    flows = []
    for i in range(n):
        offset = 0.0
        if jitter_offset and i % 2 == 0:
            offset = jitter_offset
        elif jitter_offset:
            offset = -jitter_offset
        ts = 1000.0 + i * interval + offset
        flows.append((src, dst, dport, sport_base + i, ts, pkts, byts))
    return flows


# ---------------------------------------------------------------------
# базовые сценарии
# ---------------------------------------------------------------------

def test_beaconing_detects_periodic():
    """25 соединений с интервалом 60 сек — типичный C2 heartbeat."""
    flows = _regular_flows(n=25, interval=60.0)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert len(findings) == 1
    assert findings[0].type == "beaconing"
    assert findings[0].evidence["count"] == 25
    assert findings[0].confidence > 0.7
    assert findings[0].evidence["mean_interval_sec"] == 60.0


def test_beaconing_ignores_irregular():
    """Те же 25 соединений, но с большим jitter — это не beacon."""
    flows = []
    ts = 1000.0
    for i in range(25):
        ts += 30.0 if i % 2 == 0 else 230.0
        flows.append(("192.168.1.100", "203.0.113.5", 443, 50000 + i, ts, 5, 500))
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_below_min_connections():
    """5 соединений — меньше порога 20."""
    flows = _regular_flows(n=5)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert findings == []


def test_beaconing_ignores_large_transfers():
    """Регулярные соединения, но с большим объёмом — не heartbeat."""
    flows = _regular_flows(n=25, byts=500_000)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert findings == []


def test_beaconing_below_min_duration():
    """
    25 соединений с интервалом 20 сек.

    duration = 24 * 20 = 480 < 600 → не finding.
    rate = 25 / (480/60) = 3.125 < 5 → rate не мешает.
    """
    flows = _regular_flows(n=25, interval=20.0)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert findings == []


# ---------------------------------------------------------------------
# jitter / confidence
# ---------------------------------------------------------------------

def test_beaconing_confidence_scales_with_jitter():
    """Меньше jitter — выше confidence. Все три уровня в окне jitter<0.1."""
    # Идеальный интервал 60.0, jitter = 0
    flows_perfect = _regular_flows(n=25, interval=60.0, jitter_offset=0.0)
    # ±1 → интервалы 58/62, pstdev=2, jitter ≈ 0.033
    flows_low = _regular_flows(n=25, interval=60.0, jitter_offset=1.0)
    # ±2 → интервалы 56/64, pstdev=4, jitter ≈ 0.067
    flows_mid = _regular_flows(n=25, interval=60.0, jitter_offset=2.0)

    f_perfect = BeaconingDetector().run(_beacon_state(flows_perfect), Config())
    f_low = BeaconingDetector().run(_beacon_state(flows_low), Config())
    f_mid = BeaconingDetector().run(_beacon_state(flows_mid), Config())

    assert len(f_perfect) == 1
    assert len(f_low) == 1
    assert len(f_mid) == 1

    c_perfect = f_perfect[0].confidence
    c_low = f_low[0].confidence
    c_mid = f_mid[0].confidence

    # 0.85 > 0.767 > 0.683
    assert c_perfect > c_low > c_mid
    assert c_perfect >= 0.80
    assert c_mid >= 0.65


# ---------------------------------------------------------------------
# агрегация и группировка
# ---------------------------------------------------------------------

def test_beaconing_aggregates_by_flow_key():
    """Разные src_ports, но один (src_ip, dst_ip, dst_port) — один group."""
    flows = _regular_flows(n=25)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert len(findings) == 1
    assert findings[0].evidence["count"] == 25


def test_beaconing_separate_targets():
    """Два разных dst → два finding'а."""
    flows = []
    flows += _regular_flows(n=25, dst="203.0.113.5", sport_base=50000)
    flows += _regular_flows(n=25, dst="203.0.113.6", sport_base=60000)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert len(findings) == 2
    values = sorted(f.value for f in findings)
    assert values == [
        "192.168.1.100 -> 203.0.113.5:443",
        "192.168.1.100 -> 203.0.113.6:443",
    ]


# ---------------------------------------------------------------------
# allowlist SNI / Host / IP
# ---------------------------------------------------------------------

def test_beaconing_skips_allowlist_sni():
    """Chrome keepalive к google-analytics.com не должен быть beaconing."""
    flows = _regular_flows(n=25, byts=200)
    state = _beacon_state(flows, sni="www.google-analytics.com")
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_skips_allowlist_sni_doubleclick():
    """stats.g.doubleclick.net — analytics CDN."""
    flows = _regular_flows(n=25, byts=200)
    state = _beacon_state(flows, sni="stats.g.doubleclick.net")
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_skips_allowlist_http_host():
    """HTTP Host из allowlist → skip."""
    flows = _regular_flows(n=25, byts=200)
    state = _beacon_state(flows, http_host="www.google-analytics.com")
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_skips_allowlist_dst_ip():
    """dst_ip из beaconing_allowlist_ips → skip."""
    flows = _regular_flows(n=25, dst="1.2.3.4", byts=200)
    state = _beacon_state(flows)
    cfg = Config(beaconing_allowlist_ips=frozenset({"1.2.3.4"}))
    findings = BeaconingDetector().run(state, cfg)
    assert findings == []


def test_beaconing_non_allowlist_sni_still_detected():
    """SNI, которого нет в allowlist, не должен глушить finding."""
    flows = _regular_flows(n=25, byts=400)
    state = _beacon_state(flows, sni="c2.attacker.evil")
    findings = BeaconingDetector().run(state, Config())
    assert len(findings) == 1


# ---------------------------------------------------------------------
# payload variance
# ---------------------------------------------------------------------

def test_beaconing_rejects_variable_payload_size():
    """
    C2 = const payload. Browser = разный.

    avg ≈ 730 < 5000 (старая проверка пропустила бы).
    stddev/mean ≈ 0.85 > 0.5 → ловит новый фильтр.
    """
    sizes = [100, 800, 200, 1500, 300, 900, 150, 2000, 250, 1100]
    flows = []
    for i in range(25):
        ts = 1000.0 + i * 60.0
        flows.append((
            "192.168.1.100", "203.0.113.5", 443, 50000 + i,
            ts, 5, sizes[i % len(sizes)],
        ))
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_accepts_const_payload():
    """Const payload → фильтр не мешает."""
    flows = _regular_flows(n=25, byts=400)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert len(findings) == 1


# ---------------------------------------------------------------------
# rate check
# ---------------------------------------------------------------------

def test_beaconing_rejects_parallel_burst():
    """
    100 соединений за ~11 минут.

    duration = 99 * 7 = 693 > 600 (duration OK).
    rate = 100 / 11.55 ≈ 8.66/min > 5 → rate check рубит.
    """
    flows = _regular_flows(n=100, interval=7.0)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert findings == []


def test_beaconing_rate_check_not_triggered_for_slow_beacon():
    """60-секундный интервал = 1 flow/min, rate не мешает."""
    flows = _regular_flows(n=25, interval=60.0)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert len(findings) == 1


# ---------------------------------------------------------------------
# skip internal
# ---------------------------------------------------------------------

def test_beaconing_skips_internal_dst():
    """
    C2 обычно external. internal → internal — отдельная история.
    """
    flows = _regular_flows(
        n=25, dst="192.168.1.200", dport=5985, byts=200,
    )
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert findings == []


def test_beaconing_internal_dst_not_skipped_when_disabled():
    """Если skip отключён, internal → internal находится."""
    flows = _regular_flows(
        n=25, dst="192.168.1.200", dport=5985, byts=200,
    )
    cfg = Config(beaconing_skip_internal_dst=False)
    findings = BeaconingDetector().run(_beacon_state(flows), cfg)
    assert len(findings) == 1


# ---------------------------------------------------------------------
# threshold boundary
# ---------------------------------------------------------------------

def test_beaconing_threshold_boundary():
    """19 flows — нет, 20 — да."""
    f19 = BeaconingDetector().run(
        _beacon_state(_regular_flows(n=19)), Config(),
    )
    f20 = BeaconingDetector().run(
        _beacon_state(_regular_flows(n=20)), Config(),
    )
    assert f19 == []
    assert len(f20) == 1


# ---------------------------------------------------------------------
# регрессия: настоящий C2 должен ловиться после всех новых фильтров
# ---------------------------------------------------------------------

def test_beaconing_real_c2_still_detected():
    """
    Все фильтры против настоящего C2:
    - dst external, не в allowlist IP
    - SNI не в allowlist
    - 25 connections, 60s ± 1s → jitter ≈ 0.033
    - const payload 400B
    - rate ≈ 1/min
    """
    flows = _regular_flows(
        n=25, interval=60.0, jitter_offset=1.0,
        dst="8.8.8.8", dport=8443, byts=400,
    )
    state = _beacon_state(flows, sni="c2.attacker.evil")
    findings = BeaconingDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].type == "beaconing"
    assert findings[0].confidence >= 0.7


# ---------------------------------------------------------------------
# multi-tenant filter (0.7.0)
# ---------------------------------------------------------------------

def test_beaconing_skips_multi_tenant_cdn():
    """
    Chrome к Akamai: 25 соединений к одному IP, но SNI разные.
    C2 использует ОДИН домен. >1 уникального SNI = shared edge.
    """
    flows = _regular_flows(n=25, byts=400)
    sni_list = [
        "a248.e.akamai.net",
        "e1234.dscx.akamaiedge.net",
        "safebrowsing.google.com",
        "c.go-mpulse.net",
        "e5678.g.akamaiedge.net",
    ]
    state = _beacon_state(flows, sni_list=sni_list)
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_skips_multi_tenant_mixed_sni_host():
    """
    SNI + HTTP Host считаются вместе. 1 SNI + 1 Host = 2 destinations.
    """
    flows = _regular_flows(n=25, byts=400)
    state = _beacon_state(
        flows,
        sni="cdn.example.net",
        http_host="telemetry.example.net",
    )
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_single_sni_not_in_allowlist_detected():
    """Один SNI, не в allowlist → finding."""
    flows = _regular_flows(n=25, byts=400)
    state = _beacon_state(flows, sni="c2.attacker.evil")
    findings = BeaconingDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["unique_destinations"] == ["c2.attacker.evil"]


def test_beaconing_no_sni_single_ip_detected():
    """Нет SNI/Host (raw IP) → всё ещё C2-кандидат."""
    flows = _regular_flows(n=25, byts=400)
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["unique_destinations"] == []


# ---------------------------------------------------------------------
# mail-port filter (0.7.0)
# ---------------------------------------------------------------------

def test_beaconing_skips_pop3():
    """Порт 110 = POP3. Mail polling — не C2."""
    flows = _regular_flows(n=25, dport=110, byts=400)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert findings == []


def test_beaconing_skips_imap():
    """Порт 143 = IMAP."""
    flows = _regular_flows(n=25, dport=143, byts=400)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert findings == []


def test_beaconing_skips_imaps_pop3s():
    """993 = IMAPS, 995 = POP3S."""
    for port in (993, 995):
        flows = _regular_flows(n=25, dport=port, byts=400)
        findings = BeaconingDetector().run(_beacon_state(flows), Config())
        assert findings == [], f"port {port} should be skipped"


def test_beaconing_smtp_not_skipped():
    """
    SMTP (25) НЕ в mail-фильтре. Malware может использовать SMTP-туннель.
    """
    flows = _regular_flows(n=25, dport=25, byts=400)
    findings = BeaconingDetector().run(_beacon_state(flows), Config())
    assert len(findings) == 1


# ---------------------------------------------------------------------
# прочее
# ---------------------------------------------------------------------

def test_beaconing_ignores_udp():
    """UDP не считается — beaconing на TCP."""
    state = CaptureState()
    for i in range(25):
        key = FlowKey(
            proto="udp", src_ip="192.168.1.100", dst_ip="203.0.113.5",
            src_port=50000 + i, dst_port=53,
        )
        fs = FlowStats(packets=2, bytes_sent=100)
        fs.first_ts = 1000.0 + i * 60.0
        fs.last_ts = fs.first_ts + 0.5
        state.flows[key] = fs
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_empty_state():
    """Пустой CaptureState — не падает."""
    findings = BeaconingDetector().run(CaptureState(), Config())
    assert findings == []