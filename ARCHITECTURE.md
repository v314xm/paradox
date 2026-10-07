# Архитектура pcap-triage

## Модель

Конвейер преобразований. Каждый слой решает одну задачу и передаёт
результат следующему. Слои не знают друг о друге, общаются только
через структуры данных.

    PCAP → Extractors → CaptureState → Detectors → Findings
                                                  ↓
                                              Correlator → Entities → Reporters

## Принципы

1. Разделение extract / detect / correlate / report.
2. Данные текут в одном направлении.
3. Каждый слой — реестр плагинов.

## Слои

### Extractors

Единственное место, где живут scapy/dpkt. Реестр независимых
экстракторов, по одному на протокол или тип данных.

Два потока событий:
- низкоуровневые пакеты — всем экстракторам сразу;
- реассемблированные TCP-потоки — отдельным потоком (позже).

Изоляция ошибок: падение одного экстрактора не роняет проход,
ошибки считаются в `state.extractor_errors`.

Порядок важен: `FlowExtractor` идёт **первым**. Остальные L0
независимы. Будущие L2 (TLS/HTTP/SMB) ищут существующий
`FlowStats` по `FlowKey` и падают явно, если его нет.

### CaptureState

Нормализованное представление захвата. Никакого scapy внутри.

Содержит:
- `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`
- `flows: dict[FlowKey, FlowStats]`
- мета: `packet_count`, `first_ts`, `last_ts`, `extractor_errors`

`FlowStats` — точка сборки контекста сессии. Базовая телеметрия
(`packets`, `bytes_sent`, `first_ts`, `last_ts`, `timestamps`) плюс
протокол-специфичные поля (`sni`, `ja3`, `http_host`, `http_user_agent`).

**Windowing — отложено, запланировано.** Когда появится beaconing,
потребуется последовательность временных окон плюс глобальный агрегат.

### Detectors

Чистые функции над `CaptureState`. Никакого scapy.

Две семьи по стоимости:
- **LocalDetector** — над state, локально, дёшево.
- **EnrichmentDetector** — над уже скоррелированными `EntityRisk`,
  сетевой вызов, rate limit. Threat Intel.

Кросс-слойные детекторы (читают два и более раздела state) — самая
ценная категория. Например, SNI mismatch читает и `dns_queries`,
и `flows.sni`.

### Findings

Структурированный результат. `type`, `value`, `confidence`,
`evidence`, `first_seen`, `last_seen`. Единица обмена между слоями.

### Correlator (план)

Группирует findings по сущности (IP, домен), считает композитный
риск. Две работы: entity scoring (кто подозрителен) и timeline
construction (что произошло).

### Reporters

Превращают findings + entities в артефакты: JSON, flow report
(conn.log-стиль), позже — CLI-таблица, SIEM-адаптер, IncidentReport,
IOCExport.

## Порядок внедрения

1. DNS-экстрактор + DGA + JSON — **сделано**
2. FlowExtractor + flow report — **сделано**
3. SuspiciousPort — **сделано**
4. NXDOMAINBurst, CloudTunnel, IPCheckService, Typosquatting — **сделано**
5. Windowing — следующее
6. BeaconingDetector
7. StreamReassembler + TLSExtractor + SNIMismatch
8. HTTPExtractor + HTTPObject + ScriptFile + Obfuscation
9. Correlator (entity scoring)
10. Threat Intel enrichment
11. Kerberos + LDAP + HostIdentity
12. AD-детекторы
13. Timeline + IncidentReport + IOCExport
14. Streamlit → FastAPI

## Известные долги

- `timestamps` в `FlowStats` растут неограниченно → Welford
- `FlowKey` не нормализует направление → канонизация
- TLS-парсер ручной → нужен reassembly и JA3
- DGA по энтропии → false positives на CDN, расширять allowlist
- `nxdomain_burst` считает за весь файл → должен быть по окну