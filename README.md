# pcap-triage

Инструмент, который ищет **противоречия между слоями данных**
в сетевом захвате: DNS vs SNI, JA3 vs User-Agent, MAC vs IP,
роли vs поведение. Показывает не только находки, но и **что
из них не сходится** — пивоты, ARP-spoof, domain-fronting,
протокольные туннели.

**Задача:** аналитик получает не плоский список из 500 flows,
а структурированный профиль хостов, набор findings и — главное —
**список несогласованностей**, которые указывают на скрытые
сценарии: хост, который одновременно жертва и атакующий (pivot);
IP, отвечающий двумя MAC (ARP-spoof); SNI, не совпадающий с
Host (domain fronting).

Работает оффлайн. Никаких внешних API — только локальный разбор.

## Чем отличается от других

Zeek, Arkime, tshark, Rita — сотни инструментов парсят pcap
и находят то же самое: DNS-запросы, TLS-хендшейки, HTTP.
**Никто из них не проверяет согласованность между слоями данных.**

pcap-triage строит из pcap **атомарные факты** о мире:
(192.168.1.12, victim_of, 10.0.1.50, ts, "finding", 0.85)
(192.168.1.12, attacker_of, 192.168.1.1, ts, "finding", 0.80)
(192.168.1.5, has_mac, 00:60:6e:00:9d:f9, ts, "arp", 0.9)
(192.168.1.5, has_mac, aa:bb:cc:dd:ee:02, ts, "arp", 0.6)


И ищет противоречия: два MAC на одном IP (ARP-spoof), два
противоположных утверждения о роли хоста (pivot), SNI ≠ Host
(domain fronting). Это **новый слой анализа**, поверх findings
и поверх entities.

## Что делает

Из одного pcap-файла:

- **Профиль жертвы.** IP, MAC, hostname, username, realm — из
  ARP, NBNS, Kerberos. Собирается автоматически.
- **C2-инфраструктура.** DGA, cloud tunnels, typosquatting,
  IP-check сервисы, SNI без DNS.
- **C2-beaconing.** Периодические heartbeat-соединения
  (jitter < 0.1, ≥ 20 обращений, ≥ 10 минут).
- **DNS tunneling.** Длинные уникальные поддомены под одним
  базовым доменом.
- **Активная разведка.** Web-сканеры, port-сканеры, FTP-брутфорс.
- **Lateral movement.** WinRM, PsExec, SMB, RDP между внутренними
  хостами.
- **Эксфильтрация.** Large transfers (100 МБ+) и reverse
  asymmetry (10:1 при объёме ≥ 1 МБ).
- **Payload download.** Скрипты (.ps1, .sh, .vbs, .hta),
  бинарники из HTTP-ответов. Metadata-only, тело на диск не пишется.
- **Роли хостов.** `domain_controller`, `victim_candidate`,
  `attacker_candidate`, `c2_candidate`, `gateway_candidate`,
  `pivot`.
- **Противоречия.** 7 правил, см. секцию ниже.

## Противоречия (ContradictionDetector)

Новый слой анализа поверх findings. Не детекторы атак, а поиск
**несогласованностей между источниками**: одно утверждение о мире
подтверждается одним источником и опровергается другим.

| Правило | Severity | Что находит |
|---|---|---|
| `victim_makes_attack` | critical | Хост одновременно жертва и атакующий → pivot |
| `mac_ip_conflict` | critical | ARP-spoof: два MAC на одном IP |
| `sni_host_mismatch` | high | Domain fronting: SNI ≠ HTTP Host |
| `ja3_ua_mismatch` | high | JA3 tool + browser UA → мимикрия скрипта |
| `reverse_asymmetry` | medium | Пропорция сессии 10:1 (эксфильтрация) |
| `port_service_mismatch` | high | TLS на 22, HTTP на 445 → туннель |
| `direct_ip_no_dns` | medium | Клиент ходит на IP без DNS-резолва |

На CyberCampTask pivot-правило находит `192.168.1.12` — хост,
которого сначала атакуют (brute_force), а затем он сам атакует
(lateral movement на шлюз). Классический сценарий компромисса.

## Быстрый старт

```powershell
# Установка (один раз)
pip install -e .

# Запуск
python -m pcap_triage capture.pcap
Отчёт появится в reports/capture_pcap.report.json и
reports/capture_pcap.report.md.

Без аргументов — спросит путь интерактивно:

python -m pcap_triage

packets:            627694
unique DNS queries: 117
NXDOMAIN count:     0
flows:              2328
findings:           7
report JSON:        reports\CyberCampTask_pcap.report.json
report Markdown:    reports\CyberCampTask_pcap.report.md
## Противоречия (1)

🔴 victim_makes_attack — 192.168.1.12 (0.80)

> 192.168.1.12 сначала атакован (10.0.1.50, ts=1754924349.1),
> потом сам атакует (192.168.1.1, ts=1754924987.7).
> Классический pivot — проверить сессии 192.168.1.12.

Факты:
- victim_of ← 10.0.1.50 [brute_force] (source=finding, conf=0.85)
- attacker_of ← 192.168.1.1 [lateral_movement] (source=finding, conf=0.80)

Вероятные причины:
- Хост скомпрометирован: сначала атакован, потом сам атакует
- Authorized scanner в сети
- NAT/proxy: одна IP скрывает несколько хостов
- FP одной из эвристик
В сущностях этот хост получает роль pivot поверх victim_candidate.

Производительность
334 МБ pcap (627k пакетов) — 19 секунд

152 МБ pcap (232k пакетов, с TCP reassembly) — 12 секунд

9.5M пакетов (58 файлов, 4.7 ГБ) — 10 минут полный батч

Память — 106 МБ на 334 МБ файл

В основе — собственный парсер пакетов на struct.unpack,
без scapy dissect. Это даёт 39x ускорение против чистого scapy.
Scapy используется точечно — только для сложных payload.

Что внутри
Экстракторы (8)
Слой	Модуль	Что извлекает
L0	flow.py	5-tuple, байты, timestamps, инициатор
L0	dns.py	DNS-запросы, NXDOMAIN, по источнику
L0	host_identity.py	MAC из ARP
L0	arp_history.py	История MAC на IP (для ARP-spoof)
L0	nbns.py	Hostname из NBNS (NetBIOS)
L0	kerberos.py	Username, realm, sname из Kerberos
L0	tls.py	SNI + JA3 из TLS ClientHello
L0	http.py	Host, URI, Method, User-Agent
Плюс reassembler.py — склейка TCP-сегментов, http_object.py —
полные HTTP запросы/ответы из потока, file_carve.py — метаданные
payload'ов (sha256, MIME, первые 64 байта).

Детекторы (17)
C2 / инфраструктура: dga, cloud_tunnel, ip_check_service,
typosquatting, sni_mismatch, suspicious_port.

Активность: port_scan, web_scanner (в vulnerable_path),
brute_force, ftp_brute_force.

Коммуникации: beaconing, dns_tunneling, lateral_movement,
large_transfer.

Payload: vulnerable_path (уязвимые пути + скачивание
скриптов), command_injection (RCE в URI и POST body),
ja3_malware (TLS-фреймворки C2).

Meta: nxdomain_burst.

Каждый детектор пишет универсальные поля в evidence:
src_ip, dst_ip, dst_port, first_seen, last_seen.

Правила ContradictionDetector (7)
victim_makes_attack, mac_ip_conflict, sni_host_mismatch,
ja3_ua_mismatch, reverse_asymmetry, port_service_mismatch,
direct_ip_no_dns. Реализованы как реестр, см. CONTRADICTIONS.md.

Отчёты (3)
JSON — с schema_version, provenance (sha256 pcap),
contradictions, для SIEM.

Markdown — для копирования в тикет или вики.

Flow report — conn.log-стиль, для ручного пивота в Wireshark.

###Архитектура
PCAP → Extractors → CaptureState → Detectors → Findings
                                              ↓
                              ContradictionDetector
                                (Fact extraction)
                                              ↓
                                 ContradictionRules
                                              ↓
                                  Contradictions
                                              ↓
                                    build_entities
                                    (роль pivot)
                                              ↓
                              Reporters → JSON + Markdown

Почему contradictions после detectors и до build_entities:

После detectors — потому что используют findings как факты.

До entities — потому что влияют на финальные роли (pivot —
это не «жертва или атакующий», а «жертва + атакующий»).

Полная модель — в ARCHITECTURE.md. Справочник по модулям —
в MODULES.md. Что такое contradictions — в CONTRADICTIONS.md.
История версий — в CHANGELOG.md.

Тесты
pytest tests/ -q
302 теста в 21 файле. Всё зелёное.

Группа	Файлов	Что покрывает
Парсеры	3	L2-L4 заголовки, TLS, NBNS, HTTP
Экстракторы	4	Flow, DNS, TLS, HTTP
Детекторы	8	17 детекторов + FP-регрессии
Aggregators	1	Роли, сущности
Contradictions	7	7 правил (по 5 тестов на правило)
Enrichment	4	Cache, провайдеры, pipeline
Проверено на
FIRST-2015 Hands-on Network Forensics — 58 pcap'ов,
9.5M пакетов, 4.7 ГБ, полный батч за 10 минут. 386 findings,
11 contradictions, 0 ошибок. Топ findings: nxdomain_burst 93,
sni_without_dns 73, script_download 50, vulnerable_path 46,
command_injection 33.

CTF CyberCampTask (334 МБ, 627k пакетов) — HTTP-брутфорс +
FTP-брутфорс + скачивание скриптов + WinRM lateral movement +
large transfer на rtbcdn.ru. 7 findings, 2 contradictions,
0 FP. Pivot-правило находит 192.168.1.12 (жертва и атакующий).

MTA 2025-06-13 — упражнение malware-traffic-analysis.net.
Профиль жертвы 5 из 5 (IP, MAC, hostname, username, realm).

Требования
Python 3.11+

scapy ≥ 2.5 (только для DNS payload + fallback pcapng)

pyyaml ≥ 6.0

Windows / Linux / macOS. Разрабатывалось под Windows.

Roadmap
0.7.0 (текущая) — ContradictionDetector, 7 правил, 302 теста.

0.8.0 — расширение видимости:

DNS-ответы (A/AAAA/CNAME-записи) — для sni_host_mismatch и
direct_ip_no_dns v2.

TLS-сертификаты (CN, SAN) — для cert_cn_sni_mismatch,
self_signed_on_external.

Универсальный контракт Finding (top-level src_ip, dst_ip,
severity, mitre_id).

Timeline / kill-chain reconstruction.

0.9.0 — новые экстракторы:

SMB2, DHCP, SSH-баннер.

HTTP/2 framing.

IPv6 в парсере.

1.0.0 — стабильный API:

STIX 2.1 экспорт IOC.

REST API + Web UI.

Плагины (пользовательские правила contradictions).

Вклад
Issues и pull requests — приветствуются. Что нужно знать:

Стиль кода — ruff check + ruff format.

Тесты — обязательны для новых правил и детекторов.

Комментарии — на русском, объясняют «почему», не «что».