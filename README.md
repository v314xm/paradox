# pcap-triage

Инструмент для первичного триажа pcap-файлов. Превращает сетевой
захват в структурированный JSON + человекочитаемый Markdown-отчёт
за секунды.

**Задача:** избавить аналитика от ручного перебора 500+ flow'ов.
Инструмент сам собирает профиль жертвы (IP, MAC, hostname, username,
realm), находит C2, скачанные скрипты, подозрительные домены и
строит компактный список сущностей для тикета.

## Что делает

Из одного pcap-файла:

- **Профиль жертвы.** IP, MAC, hostname, username, realm — из ARP,
  NBNS, Kerberos. Собирается автоматически.
- **C2-инфраструктура.** DGA, cloud tunnels, typosquatting,
  IP-check сервисы, SNI без DNS.
- **Payload download.** Скрипты (.ps1, .sh, .vbs, .hta), бинарники
  из HTTP-запросов.
- **Направление трафика.** Uploaded / downloaded / internal —
  сразу видно, загрузка это или эксфильтрация.
- **Роли хостов.** `domain_controller`, `victim_candidate`,
  `attacker_candidate`, `c2_candidate`, `gateway_candidate`.

Работает оффлайн. Никаких внешних API — только локальный разбор.

## Быстрый старт

```powershell
# Установка (один раз)
pip install -e .

# Запуск
python -m pcap_triage capture.pcap
```

Отчёт появится в `reports/capture.report.json` и `reports/capture.report.md`.

Без аргументов — спросит путь интерактивно:

```powershell
python -m pcap_triage
```

## Пример вывода

```
packets:            627694
unique DNS queries: 117
NXDOMAIN count:     0
flows:              2328
findings:           9
report JSON:        reports\capture.report.json
report Markdown:    reports\capture.report.md
```

В Markdown-отчёте — сущности с ролями и профилем:

```markdown
**`10.6.13.133`** — internal, victim_candidate
  359 flows out · 353 in · ↓ 36.6 MB · ↑ 3.6 MB
  hostname: `DESKTOP-5AVE44C`
  MAC: `24:77:03:ac:97:df`
  username: `rgaines`
  realm: `MASSFRICTION.COM`
```

## Производительность

- **334 МБ pcap** (627k пакетов) — **12 секунд**
- **50 МБ pcap** (48k пакетов) — **1.5 секунды**
- **Память** — 106 МБ на 334 МБ файл

В основе — собственный парсер пакетов на `struct.unpack`,
без scapy dissect. Это даёт **39x ускорение** против чистого scapy.
Scapy используется точечно — только для DNS-payload.

## Что внутри

### Экстракторы (7)

| Слой | Модуль | Что извлекает |
|---|---|---|
| L0 | `flow.py` | 5-tuple, байты, timestamps, инициатор |
| L0 | `dns.py` | DNS-запросы, NXDOMAIN, по источнику |
| L0 | `host_identity.py` | MAC из ARP |
| L0 | `nbns.py` | Hostname из NBNS (NetBIOS) |
| L0 | `kerberos.py` | Username, realm, sname из Kerberos |
| L0 | `tls.py` | SNI из TLS ClientHello |
| L0 | `http.py` | Host, URI, Method, User-Agent |

### Детекторы (10)

| Детектор | Что ловит |
|---|---|
| `dga` | Высокая энтропия label в DNS |
| `suspicious_port` | Исходящие на нестандартные порты |
| `nxdomain_burst` | Много NXDOMAIN с одного IP |
| `cloud_tunnel` | trycloudflare, ngrok, serveo |
| `ip_check_service` | ip-api.com, ifconfig.me |
| `typosquatting` | Подделки под бренды (Levenshtein) |
| `sni_mismatch` | SNI без DNS-запроса |
| `brute_force` | Перебор паролей к одному endpoint |
| `vulnerable_path` | Обращения к уязвимым путям (wp-login, .env) |
| `script_download` | Скачивание .ps1/.sh/.vbs/.jar |

### Отчёты (3)

- **JSON** — с `schema_version`, `provenance` (sha256 pcap), для SIEM.
- **Markdown** — для копирования в тикет или вики.
- **Flow report** — conn.log-стиль, для ручного пивота в Wireshark.

## Архитектура

```
PCAP → Extractors → CaptureState → Detectors → Findings
                                              ↓
                                       Aggregators (entities)
                                              ↓
                                       Reporters → JSON + Markdown
```

Полная модель — в `ARCHITECTURE.md`. Справочник по модулям — в
`MODULES.md`. История версий — в `CHANGELOG.md`.

## Тесты

```powershell
pytest tests/ -v
```

**106 тестов** в 9 файлах. Всё зелёное.

| Файл | Тестов | Что покрывает |
|---|---|---|
| `test_detectors.py` | 41 | 9 детекторов, регрессии |
| `test_parsers.py` | 11 | Разбор L2-L4 заголовков |
| `test_aggregators_entities.py` | 10 | Роли, сущности, findings |
| `test_tls_parse.py` | 10 | TLS ClientHello |
| `test_brute_force.py` | 9 | Детектор перебора |
| `test_extractors_http.py` | 8 | HTTP-экстрактор |
| `test_net_utils.py` | 6 | Направление трафика |
| `test_extractors_tls.py` | 6 | TLS-экстрактор |
| `test_nbns_parse.py` | 5 | NBNS (NetBIOS) |

## Проверено на

- **MTA 2025-06-13** — упражнение malware-traffic-analysis.net.
  Инструмент собрал профиль жертвы **5 из 5** (IP, MAC, hostname,
  username, realm) за 1.5 секунды. Ручной разбор занимает 30–40 мин.
- **CTF CyberCampTask** (334 МБ) — подбор пароля + скачивание
  скриптов + C2. Все findings корректные.
- **FIRST-2015 Hands-on Network Forensics** — 3 pcap'а.
- **IDS-пакет** (WordPress `/.env`) — сканирование уязвимости.
- **MTA Simple C2** — сканер `78.153.140.203`.

## Требования

- Python 3.11+
- `scapy` ≥ 2.5 (только для DNS + fallback pcapng)
- `pyyaml` ≥ 6.0

Windows / Linux / macOS. Разрабатывалось под Windows.

## Лицензия

Проект 314 