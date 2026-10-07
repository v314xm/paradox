# pcap-triage

Инструмент для первичного триажа pcap-файлов. Превращает захват
в структурированный JSON-отчёт с findings по подозрительным
сущностям.

## Установка

    pip install -e .

## Запуск

    python -m pcap_triage capture.pcap

Или без аргумента — спросит путь интерактивно.

Отчёт кладётся в `reports/<имя>.report.json`.

## Тесты

    pytest tests/ -v

## Текущие детекторы

- `dga_domain` — домены с высокой энтропией label
- `suspicious_port` — соединения на порты из `config.suspicious_ports`
- `nxdomain_burst` — >= N NXDOMAIN с одного IP
- `cloud_tunnel_domain` — trycloudflare, ngrok, serveo и т.п.
- `ip_check_service` — ip-api.com, ifconfig.me и т.п.
- `typosquatting` — подделки под бренды (contains + Levenshtein)

## Архитектура

PCAP → Extractors → CaptureState → Detectors → Findings → Reporters

Подробнее — в `ARCHITECTURE.md`.