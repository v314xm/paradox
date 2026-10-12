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
- **Активная разведка.** Web-сканеры (перебор уязвимых путей),
  port-сканеры (горизонтальное сканирование портов),
  FTP-брутфорс (словарный подбор).
- **Lateral movement.** WinRM, PsExec, SMB, RDP между внутренними
  хостами. WinRM/PowerShell/Python-tools ловятся по User-Agent.
- **Эксфильтрация.** Large transfers — аномально большие объёмы
  в одном направлении (100 МБ и выше).
- **Payload download.** Скрипты (.ps1, .sh, .vbs, .hta),
  бинарники из HTTP-запросов.
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
findings:           6
report JSON:        reports\CyberCampTask_pcap.report.json
report Markdown:    reports\CyberCampTask_pcap.report.md
```

Найденные findings на этом pcap (из ручного разбора CTF —
все 6 корректные):

```
brute_force       10.0.1.50 → 192.168.1.12:80      HTTP /loginok.html
ftp_brute_force   10.0.1.50 → 192.168.1.12:21      474 попытки
lateral_movement  192.168.1.12 → 192.168.1.1:5985  Ruby WinRM Client
large_transfer    192.168.1.1 ↔ 80.64.102.71       126 MB, rtbcdn.ru
script_download   /ftp_update.sh                   Wget/1.21.3
script_download   /watch_movie.ps1                 PowerShell
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
- **9.5M пакетов** (58 файлов, 4.7 ГБ) — **8 минут** полный батч
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

### Детекторы (13)

| Детектор | Что ловит |
|---|---|
| `dga` | Высокая энтропия label в DNS |
| `suspicious_port` | Исходящие на нестандартные порты |
| `port_scan` | Горизонтальное сканирование (один src → много dst:port) |
| `nxdomain_burst` | Много NXDOMAIN с одного IP |
| `cloud_tunnel` | trycloudflare, ngrok, serveo |
| `ip_check_service` | ip-api.com, ifconfig.me — DNS, SNI, HTTP Host, прямой IP |
| `typosquatting` | Подделки под бренды (SLD-only + Levenshtein) |
| `sni_mismatch` | SNI без DNS-запроса |
| `brute_force` | HTTP-перебор паролей к login endpoint |
| `ftp_brute_force` | FTP-перебор (400+ попыток к порту 21) |
| `lateral_movement` | WinRM, PsExec, SMB, RDP между внутренними хостами |
| `large_transfer` | Flow с объёмом > 100 МБ (прямой + обратный) |
| `vulnerable_path` | Уязвимые пути (wp-login, .env) + web_scanner |

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

**145 тестов** в 10 файлах. Всё зелёное.

| Файл | Тестов | Что покрывает |
|---|---|---|
| `test_detectors.py` | 41 | 9 базовых детекторов |
| `test_regressions.py` | 26 | FP-регрессии из FIRST-2015 + CyberCampTask |
| `test_parsers.py` | 11 | Разбор L2-L4 заголовков |
| `test_aggregators_entities.py` | 10 | Роли, сущности, findings |
| `test_tls_parse.py` | 10 | TLS ClientHello |
| `test_brute_force.py` | 9 | HTTP-перебор |
| `test_extractors_http.py` | 8 | HTTP-экстрактор |
| `test_net_utils.py` | 6 | Направление трафика |
| `test_extractors_tls.py` | 6 | TLS-экстрактор |
| `test_nbns_parse.py` | 5 | NBNS (NetBIOS) |

## Проверено на

- **MTA 2025-06-13** — упражнение malware-traffic-analysis.net.
  Инструмент собрал профиль жертвы **5 из 5** (IP, MAC, hostname,
  username, realm) за 1.5 секунды. Ручной разбор занимает 30–40 мин.
- **FIRST-2015 Hands-on Network Forensics** — 58 pcap'ов,
  9.5M пакетов, 4.7 ГБ. 5872 findings → 343 после FP-оптимизации
  0.4.0. 8 минут полный батч.
- **CTF CyberCampTask** (334 МБ) — HTTP-брутфорс + FTP-брутфорс +
  скачивание скриптов + WinRM lateral movement + large transfer
  на rtbcdn.ru. **6 findings, 0 FP.** Покрыто 4 из 5 гэпов
  ручного анализа; не покрыт внутренний C2 (требует
  HTTPObjectExtractor).
- **IDS-пакет** (WordPress `/.env`) — сканирование уязвимости.
- **MTA Simple C2** — сканер `78.153.140.203`.

## Требования

- Python 3.11+
- `scapy` ≥ 2.5 (только для DNS + fallback pcapng)
- `pyyaml` ≥ 6.0

Windows / Linux / macOS. Разрабатывалось под Windows.

## Лицензия

Проект 314