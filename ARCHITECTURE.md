# Архитектура pcap-triage

## Модель

Конвейер преобразований. Каждый слой решает одну задачу и передаёт
результат следующему. Слои не знают друг о друге, общаются только
через структуры данных.

    PCAP → Extractors → CaptureState → Detectors → Findings → Reporters
                                                              ↓
                                         (план) Correlator → Entities

## Принципы

1. Разделение extract / detect / correlate / report.
2. Данные текут в одном направлении.
3. Каждый слой — реестр плагинов.

## Слои

### Extractors

Единственное место, где живут scapy/dpkt. Реестр независимых
экстракторов, по одному на протокол или тип данных.

**Уровни (план):**
- L0 пакетные: DNS, ARP, DHCP, NBNS, Flow
- L1 потоковые: StreamReassembler
- L2 протокольные: TLS, HTTP, SMB, Kerberos, LDAP, DCE/RPC
- L3 объектные: HTTPObject, SMBObject, FileCarve
- L4 склейка: HostIdentity

**Сейчас реализованы:** Flow, DNS (L0).

**Порядок важен:** `FlowExtractor` идёт **первым**. Остальные L0
независимы. Будущие L2 (TLS/HTTP) ищут существующий FlowStats
по FlowKey и должны падать явно, если его нет.

**Изоляция ошибок:** падение одного экстрактора не роняет проход,
ошибки считаются в `state.extractor_errors`.

### CaptureState

Нормализованное представление захвата. Никакого scapy внутри.

**Содержит:**
- `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`
- `flows: dict[FlowKey, FlowStats]`
- мета: `packet_count`, `first_ts`, `last_ts`, `extractor_errors`

**FlowStats** — точка сборки контекста сессии:
- базовая телеметрия: `packets`, `bytes_sent`, `first_ts`, `last_ts`,
  `timestamps`
- протокол-специфичные поля (заполняются L2): `sni`, `ja3`,
  `http_host`, `http_user_agent`

**FlowKey** — направленный 5-tuple. A→B и B→A — разные ключи.

**Windowing** — отложено. Нужно для nxdomain_burst по окну,
FastFlux, объёмного exfil. Не критично для текущих детекторов.

### Detectors

Чистые функции над `CaptureState`. Никакого scapy.

**Две семьи по стоимости (план):**
- **LocalDetector** — над state, локально, дёшево.
- **EnrichmentDetector** — над `EntityRisk`, сетевой вызов,
  rate limit. Threat Intel.

**Сейчас реализованы 6 LocalDetector:**
- DGADetector — энтропия label, игнор дефисов, allowlist
- SuspiciousPortDetector — приватные dst игнорируются, агрегация
  по (dst_ip, dst_port)
- NXDOMAINBurstDetector — count по src_ip
- CloudTunnelDetector — суффиксы cloud-туннелей
- IPCheckServiceDetector — точные домены
- TyposquattingDetector — contains + Levenshtein, legitimate-список

**Пороги и списки** — в `Config`, не в коде детекторов.

### Findings

Структурированный результат. `type`, `value`, `confidence`,
`evidence`, `first_seen`, `last_seen`. Единица обмена между слоями.

**Принцип:** finding — на **сущность**, а не на инцидент одного flow.
Пример: 474 соединения к 192.168.1.12:21 → 1 finding, а не 474.

### Reporters

Превращают findings + flows в артефакты.

**Сейчас:** JSON-отчёт, flow report (conn.log-стиль).
**План:** CLI-таблица, SIEM, IncidentReport, IOCExport, Markdown.

**Provenance обязателен:** версия инструмента, sha256 pcap.
**Детерминизм обязателен:** сортировка полей и списков.

### Correlator (план)

Группирует findings по сущности, считает композитный риск.
Две работы: entity scoring (кто подозрителен) и timeline
(что произошло). Разные структуры, разные тесты.

## Порядок внедрения

1. DNS-экстрактор + DGA + JSON — **сделано**
2. FlowExtractor + flow report — **сделано**
3. SuspiciousPort + NXDOMAINBurst + CloudTunnel + IPCheckService + Typosquatting — **сделано**
4. Прогон на реальных pcap, фиксы false positives — **сделано**
5. Оптимизация скорости парсинга — **в работе**
6. TLS SNI (простой вариант) — **приоритет после скорости**
7. Роль хостов, направление трафика, malformed-счётчик
8. FlowAggregator + BeaconingDetector
9. Windowing + nxdomain_burst по окну
10. StreamReassembler + TLSExtractor + HTTPExtractor
11. Correlator + entity scoring
12. Threat Intel enrichment
13. Kerberos + LDAP + HostIdentity + AD-детекторы
14. Timeline + IncidentReport + IOCExport
15. Streamlit → FastAPI

## Известные долги

- **Скорость парсинга:** ~3.5 МБ/с на 334 МБ. Цель 15–30 МБ/с.
  Решение — dpkt или raw-парсер (после профилирования).
- **TLS SNI отсутствует.** Все HTTPS-соединения невидимы по домену.
  Реальный pcap показал пропущенный C2-домен.
- **`timestamps` в FlowStats** — на 334 МБ дают 106 МБ RAM,
  не критично. Welford отложен.
- **FlowKey не нормализует направление** — нужно для exfil-детекторов.
- **Направление трафика** в flow report не показывается
  (download/upload не различаются).
- **Malformed packets** не считаются.
- **DGA по энтропии** — false positives на CDN/Azure,
  растить allowlist по мере поступления.
- **nxdomain_burst считает за весь файл** — должен быть по окну.