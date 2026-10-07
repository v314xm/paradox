# Архитектура pcap-triage

## Модель

Конвейер преобразований. Слои не знают друг о друге, общаются
только через структуры данных.

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
                                            Findings + Entities
                                                    │
                                                    ▼
                                            Reporters (JSON, MD)

## Принципы

1. Разделение extract / detect / aggregate / report.
2. Односторонний поток данных.
3. Реестр плагинов для каждого слоя.
4. Finding — на сущность, не на инцидент одного flow.
5. Отчёт — расширяемая схема с reserved-полями.

## Парсинг: почему не scapy

Профилирование на 334 МБ pcap: 74% времени уходило на
`scapy.packet.Packet.dissect`. Решение — `RawPcapReader` +
`struct.unpack`. Все L2-L4 заголовки разбираются за наносекунды.

Скорость: **458 → 12 секунд** (39x).

Scapy остаётся точечно — для DNS payload (сложная структура,
пакетов мало). TLS ClientHello уже разбирается вручную.

## Модули

### `parsers.py` — PacketRecord

Все L2-L4 заголовки разобраны сразу. Поля:
- мета: `ts`, `length`, `raw`
- L2: `eth_src`, `eth_dst`, `ethertype`, `vlan_id`
- L3: `src_ip`, `dst_ip`, `ip_proto`, `ip_id`, `ip_frag_offset`, `ip_mf`
- L4: `proto`, `src_port`, `dst_port`
- TCP: `tcp_seq`, `tcp_ack`, `tcp_flags`
- ARP: `arp_op`, `arp_sender_mac`, `arp_sender_ip`, `arp_target_mac`, `arp_target_ip`
- `payload: bytes` (не парсим — экстракторы по требованию)

### `models.py` — контракты

**`FlowKey`** — направленный 5-tuple. A→B и B→A — разные ключи.

**`SessionKey`** — двунаправленный ключ. A→B и B→A дают один ключ.
Строится через `make_session_key()`. Используется для `session_sni`.

**`FlowStats`** — статистика flow: packets, bytes_sent, first_ts,
last_ts, timestamps, initiated_by_src, sni, ja3, http_*.

**`CaptureState`** — состояние захвата:
- `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`
- `dns_queries_by_src: dict[str, Counter]`
- `flows: dict[FlowKey, FlowStats]`
- `session_sni: dict[SessionKey, str]`
- `packet_count`, `first_ts`, `last_ts`, `extractor_errors`
- `unsupported: dict[str, int]`
- `enrichment_budget_exhausted: bool` (заготовка VT)

**`get_session_sni(key, flow, state)`** — SNI flow из `flow.sni`
или через `session_sni`. Так SNI виден обоим направлениям.

### `extractors/` — L0 пакетные

Порядок **важен**: `FlowExtractor` идёт первым. Остальные ищут
существующий `FlowStats` по `FlowKey` и **падают явно**, если его нет.

- `FlowExtractor` — базовая телеметрия + `initiated_by_src` по SYN
- `DNSExtractor` — только порт 53, scapy DNS(payload), `dns_queries_by_src`
- `TLSExtractor` — SNI, пишет в `flow.sni` и `session_sni`

### `detectors/` — чистые функции

Никакого scapy. Читают `CaptureState`, возвращают `Finding[]`.

Семь детекторов:
- `DGADetector`, `SuspiciousPortDetector`, `NXDOMAINBurstDetector`,
  `CloudTunnelDetector`, `IPCheckServiceDetector`,
  `TyposquattingDetector`, `SNIMismatchDetector`

Принцип агрегации: **finding на сущность**. Пример:
474 соединения к 192.168.1.12:21 → 1 finding, а не 474.

### `aggregators/entities.py` — сущности

`build_entities(state, findings, config)` группирует flows и findings
по IP. Роли: `internal`/`external`, `gateway_candidate`,
`victim_candidate`, `c2_candidate`.

Special-IP фильтр: multicast, loopback, link-local, broadcast
(включая x.x.x.0 и x.x.x.255 для /24).

### `reporters/` — сериализация

**JSON** — `write_json(report_dict, path)`. Детерминирован через
`sort_keys=True`.

**Markdown** — `write_markdown(report_dict, path)`. Человекочитаемая
версия для тикета: header, сводка, сущности, findings, IOC, топ flows.

**Flow report** — `build_flow_report` (топ по байтам и пакетам,
с direction и SNI) + `build_dns_report`.

## Схема отчёта v0.2

```json
{
  "schema_version": "0.2.0",
  "provenance": {"tool_version", "pcap_path", "pcap_sha256"},
  "summary": {
    "packets", "flows", "findings", "nxdomain_count",
    "unique_dns_queries", "extractor_errors",
    "uploaded_bytes", "downloaded_bytes",
    "internal_bytes", "external_bytes"
  },
  "entities": {
    "internal": [{"ip", "roles", "flows_out", "flows_in",
                  "bytes_out", "bytes_in", "sni_domains",
                  "dns_names", "findings_indices",
                  "mac", "hostname", "username", "asn", "country"}],
    "external": [...]
  },
  "dns": {
    "unique_count", "total_queries",
    "top_by_count": [{"name", "count"}],
    "nxdomain": [{"name", "count"}]
  },
  "flows": {
    "total_flows", "top_by_bytes", "top_by_packets"
  },
  "findings": [...]
}