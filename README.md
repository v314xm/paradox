# pcap-triage

Инструмент для первичного триажа pcap-файлов. Превращает захват
в структурированный отчёт (JSON + Markdown) с сущностями, findings
и IOC по подозрительным сущностям.

## Установка

    pip install -e .

## Запуск

    python -m pcap_triage capture.pcap

Или без аргумента — спросит путь интерактивно.

Во время парсинга показывается прогресс-бар (процент, пакеты, время).
Отчёт кладётся в `reports/<имя>.report.json` и `reports/<имя>.report.md`.

## Тесты

    pytest tests/ -v

## Что в отчёте

- `provenance` — версия, sha256 pcap, путь
- `summary` — пакеты, flows, findings, uploaded/downloaded bytes
- `entities` — хосты: internal/external, роли, flows, bytes, SNI, DNS
- `dns` — список DNS-запросов + топ по частоте + NXDOMAIN
- `flows` — топ-100 по байтам и пакетам, с direction и SNI
- `findings` — список находок детекторов
- Markdown-версия — то же, но человекочитаемо (для тикета)

## Текущие экстракторы

- **FlowExtractor** — 5-tuple, bytes, timestamps, `initiated_by_src`
- **DNSExtractor** — DNS-запросы и NXDOMAIN; `dns_queries_by_src`
- **TLSExtractor** — SNI из ClientHello, ручной парсер; пишет в оба
  направления через `session_sni`

## Текущие детекторы

- `dga_domain` — высокая энтропия label (игнорирует дефисы)
- `suspicious_port` — исходящие на подозрительные порты
  (игнорирует приватные dst, агрегирует по (dst_ip, dst_port))
- `nxdomain_burst` — >= N NXDOMAIN с одного IP
- `cloud_tunnel_domain` — trycloudflare, ngrok, serveo
- `ip_check_service` — ip-api.com, ifconfig.me
- `typosquatting` — contains + Levenshtein
- `sni_without_dns` — SNI, которого нет в DNS (DoH, fronting, hardcode)

## Сущности (Entities)

Один IP = одна сущность. Вместо 500 flow-строк — 20-50 хостов
с ролями:

- `internal` / `external` — базовая классификация
- `gateway_candidate` — internal с большим числом исходящих
- `victim_candidate` — internal с findings
- `c2_candidate` — external с findings

Для каждого хоста: flows in/out, bytes in/out, SNI-домены,
DNS-имена, references на findings.

## Direction

Для каждой flow-записи:
- `inbound` — внешний → внутренний (download)
- `outbound` — внутренний → внешний (upload)
- `internal` — внутренний → внутренний
- `external` — внешний → внешний

В summary — суммы `uploaded_bytes` / `downloaded_bytes` /
`internal_bytes` / `external_bytes`.

## Производительность

Парсинг — собственный, на `RawPcapReader` + `struct`, без scapy
для L2-L4. Scapy только для DNS payload (порт 53).

На 334 МБ pcap (627 694 пакетов): **~12 секунд**. Через scapy
было бы ~460 секунд (39x разница).

## Проверено на

- Синтетика (`make_test_pcap.py`) — 36 пакетов, 14 findings
- FIRST-2015 Hands-on Network Forensics — snort.log.*
- CTF CyberCampTask — 627 694 пакета, 334 МБ, 2328 flows.
  C2-домены `salam-spbsed-*.rtbcdn.ru` видны в entities и SNI,
  но не флагуются эвристиками — резолвятся через DNS.
  Это класс задач для Threat Intel.

## Архитектура

PCAP → Extractors → CaptureState → Detectors → Findings
                                       ↓
                                  Entities → Reporters (JSON+MD)

Подробнее — в `ARCHITECTURE.md`.