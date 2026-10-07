# Архитектура pcap-triage

## Модель

Конвейер преобразований. Каждый слой решает одну задачу и передаёт
результат следующему. Слои не знают друг о друге, общаются только
через структуры данных.

    PCAP
      │
      ▼
    RawPcapReader ──► parse_packet (struct) ──► PacketRecord
                                                    │
                                                    ▼
                                                Extractors
                                                    │
                                                    ▼
                                                CaptureState
                                                    │
                                                    ▼
                                                Detectors
                                                    │
                                                    ▼
                                                 Findings
                                                    │
                                                    ▼
                                                 Reporters → JSON

## Принципы

1. Разделение extract / detect / correlate / report.
2. Данные текут в одном направлении.
3. Каждый слой — реестр плагинов.
4. Finding — на сущность, не на инцидент одного flow.

## Парсинг: почему не scapy

Профилирование на 334 МБ pcap показало: 74% времени уходило
на `scapy.packet.Packet.dissect` — построение дерева слоёв для
каждого пакета. Мы используем 6 полей из пакета, а scapy строит
полную объектную модель.

Решение: `RawPcapReader` + свой парсер через `struct.unpack`.
Все L2-L4 заголовки разбираются дёшево (наносекунды на пакет),
`raw` сохраняется как escape hatch, `payload` не парсится —
это работа экстракторов по требованию.

Скорость на 334 МБ: **458 сек → 12 сек** (39x).

Scapy остаётся для payload сложной структуры. Сейчас — только
DNS (порт 53, пакетов мало). В будущем — TLS ClientHello уже
ручной, остальное по потребности.

## Слои

### PacketRecord (parsers.py)

Нормализованный пакет. Все поля — простые типы:
- мета: `ts`, `length`, `raw`
- L2: `eth_src`, `eth_dst`, `ethertype`, `vlan_id`
- L3: `src_ip`, `dst_ip`, `ip_proto`, `ip_id`, `ip_frag_offset`, `ip_mf`
- L4: `proto`, `src_port`, `dst_port`
- TCP: `tcp_seq`, `tcp_ack`, `tcp_flags`
- ARP: `arp_op`, `arp_sender_mac`, `arp_sender_ip`,
  `arp_target_mac`, `arp_target_ip`
- `payload: bytes`

Поддерживается: Ethernet, 802.1Q VLAN, IPv4 (+фрагментация),
TCP, UDP, ICMP, ARP. IPv6 — заглушка (`proto="other"`).

### Extractors

Единственное место, где живут scapy/struct. Реестр независимых
экстракторов, по одному на протокол или тип данных.

**Уровни (план):**
- L0 пакетные: DNS, ARP, DHCP, NBNS, Flow
- L1 потоковые: StreamReassembler
- L2 протокольные: TLS, HTTP, SMB, Kerberos, LDAP, DCE/RPC
- L3 объектные: HTTPObject, SMBObject, FileCarve
- L4 склейка: HostIdentity

**Сейчас реализованы L0:** Flow, DNS, TLS (SNI).

**Порядок важен:** `FlowExtractor` идёт **первым**. Остальные
экстракторы, пишущие в `FlowStats`, ищут существующий flow
по `FlowKey` и **падают явно**, если его нет. Это ловит ошибку
порядка регистрации сразу, а не молча теряет данные.

**Изоляция ошибок:** падение одного экстрактора не роняет проход,
ошибки считаются в `state.extractor_errors`.

### CaptureState

Нормализованное представление захвата. Никакого scapy внутри.

**Содержит:**
- `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`
- `flows: dict[FlowKey, FlowStats]`
- мета: `packet_count`, `first_ts`, `last_ts`, `extractor_errors`

**FlowStats** — точка сборки контекста сессии:
- базовая телеметрия: `packets`, `bytes_sent`, `first_ts`,
  `last_ts`, `timestamps`
- протокол-специфичные поля: `sni`, `ja3`, `http_host`,
  `http_user_agent` (заполняются L2)

**FlowKey** — направленный 5-tuple. A→B и B→A — разные ключи.

**Windowing** — отложено. Нужно для nxdomain_burst по окну,
FastFlux, объёмного exfil. Не критично для текущих детекторов.

### Detectors

Чистые функции над `CaptureState`. Никакого scapy.

**Две семьи по стоимости (план):**
- **LocalDetector** — над state, локально, дёшево.
- **EnrichmentDetector** — над `EntityRisk`, сетевой вызов,
  rate limit. Threat Intel.

**Сейчас реализованы 7 LocalDetector:**
- `DGADetector` — энтропия label, игнор дефисов, allowlist
- `SuspiciousPortDetector` — приватные dst игнорируются,
  агрегация по (dst_ip, dst_port)
- `NXDOMAINBurstDetector` — count по src_ip
- `CloudTunnelDetector` — суффиксы cloud-туннелей
- `IPCheckServiceDetector` — точные домены
- `TyposquattingDetector` — contains + Levenshtein
- `SNIMismatchDetector` — SNI не в DNS, allowlist по суффиксу

**Пороги и списки** — в `Config`, не в коде детекторов.

### Findings

Структурированный результат. `type`, `value`, `confidence`,
`evidence`, `first_seen`, `last_seen`.

**Принцип:** finding — на **сущность**, не на инцидент одного flow.
Пример: 474 соединения к одному серверу → 1 finding.
Пример: 8 TLS-сессий к одному SNI → 1 finding.

### Reporters

Превращают findings + flows в артефакты.

**Сейчас:** JSON-отчёт, flow report (conn.log-стиль с SNI для TLS).
**План:** CLI-таблица, SIEM, IncidentReport, IOCExport, Markdown.

**Provenance обязателен:** версия инструмента, sha256 pcap.
**Детерминизм обязателен:** сортировка полей и списков.

### Correlator (план)

Группирует findings по сущности, считает композитный риск.
Две работы: entity scoring и timeline. Разные структуры.

### FlowAggregator + Beaconing (план)

Группировка flows по (src_ip, dst_ip, dst_port) со статистикой
интервалов (CV), duration, packets, bytes. Композитный suspicion
score. Beaconing detector — поверх агрегатора.

## Порядок внедрения

1. DNS + DGA + JSON — **сделано**
2. FlowExtractor + flow report — **сделано**
3. 5 детекторов (SuspiciousPort, NXDOMAINBurst, CloudTunnel,
   IPCheckService, Typosquatting) — **сделано**
4. Прогон на реальных pcap, фиксы false positives — **сделано**
5. Raw parser, 39x ускорение — **сделано**
6. TLSExtractor + SNIMismatch — **сделано**
7. Прогон на CTF, baseline 0 findings — **сделано**
8. Threat Intel enrichment (VT + SQLite) — **следующее**
9. FlowAggregator + BeaconingDetector
10. Windowing + nxdomain_burst по окну
11. StreamReassembler (для HTTP/SMB)
12. HTTPExtractor + HTTPObject + FileCarve
13. Correlator (entity scoring)
14. Kerberos + LDAP + HostIdentity + AD-детекторы
15. Timeline + IncidentReport + IOCExport
16. Streamlit → FastAPI

## Известные долги

- **Threat Intel отсутствует.** Домены вроде `salam-spbsed-*.rtbcdn.ru`
  (реальный C2 с CTF) не ловятся — резолвятся через DNS,
  паттерн читаемый. Это класс задач для VT.
- **Beaconing отсутствует.** В FIRST-2015 pcap 4 C2-серии,
  детектора нет.
- **`timestamps` в FlowStats** — на 334 МБ дают 106 МБ RAM,
  не критично. Welford отложен.
- **FlowKey не нормализует направление** — нужно для exfil.
- **IPv6 не поддерживается** в парсере (только заглушка).
- **TLS ClientHello только в одном сегменте** — без reassembly.
  Покрытие ~95%, редкие фрагментированные пропущены.
- **JA3 отсутствует** — только SNI.
- **`nxdomain_burst` считает за весь файл** — должен быть по окну.
- **Malformed packets не считаются.**
- **Роль хостов и направление трафика** не показываются в отчёте.