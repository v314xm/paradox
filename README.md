# pcap-triage

Инструмент для первичного триажа pcap-файлов. Превращает захват
в структурированный JSON-отчёт с findings по подозрительным сущностям.

## Установка

    pip install -e .

## Запуск

    python -m pcap_triage capture.pcap

Или без аргумента — спросит путь интерактивно.

Во время парсинга показывается прогресс-бар (процент, пакеты, время).
Отчёт кладётся в `reports/<имя>.report.json`.

## Тесты

    pytest tests/ -v

## Текущие детекторы

- `dga_domain` — домены с высокой энтропией label
  (игнорирует дефисы, allowlist CDN/cloud/Azure)
- `suspicious_port` — исходящие соединения на подозрительные порты
  (игнорирует приватные dst, агрегирует по (dst_ip, dst_port))
- `nxdomain_burst` — >= N NXDOMAIN с одного IP
- `cloud_tunnel_domain` — trycloudflare, ngrok, serveo и т.п.
- `ip_check_service` — ip-api.com, ifconfig.me и т.п.
- `typosquatting` — подделки под бренды (contains + Levenshtein)
- `sni_without_dns` — TLS SNI, которого нет в DNS-запросах
  (domain fronting, DoH, hardcoded C2)

## Экстракторы

- `FlowExtractor` — базовые flows (5-tuple, bytes, timestamps)
- `DNSExtractor` — DNS-запросы и NXDOMAIN (парсит payload через scapy,
  только для порта 53)
- `TLSExtractor` — SNI из TLS ClientHello (ручной парсер, без scapy,
  работает на нестандартных портах)

Парсинг пакетов — собственный, на `RawPcapReader` + `struct`.
Scapy остаётся только для payload сложной структуры (DNS).
Скорость: ~25 МБ/с на реальном железе (39x быстрее чем через scapy).

## Что в отчёте

- `provenance` — версия инструмента, sha256 pcap-файла, путь
- `summary` — пакеты, flows, находки, ошибки экстракторов
- `flows.top_by_bytes` — топ-100 соединений по трафику
  (для TLS-сессий включён `sni`)
- `flows.top_by_packets` — топ-100 соединений по пакетам
- `findings` — список находок с evidence

## Проверено на

- Синтетический тест (`make_test_pcap.py`) — 36 пакетов, 14 findings
- FIRST-2015 Hands-on Network Forensics — snort.log.1425572414,
  15 444 пакета, 580 flows, beaconing-паттерн на 4 C2 IP
  (обнаружен глазами, детектор beaconing в разработке)
- CTF CyberCampTask — 627 694 пакета, 334 МБ, 2328 flows,
  **0 findings** после фиксов allowlist. C2-домен
  `salam-spbsed-*.rtbcdn.ru` виден в `flows.top_by_bytes` через SNI,
  но не флагуется — потому что резолвится через DNS.
  Это класс задач для Threat Intel.

## Архитектура

PCAP → Extractors → CaptureState → Detectors → Findings → Reporters

Подробнее — в `ARCHITECTURE.md`.