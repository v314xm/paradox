pcap-triage
Инструмент, который ищет противоречия между слоями данных
в сетевом захвате: DNS vs SNI, JA3 vs User-Agent, MAC vs IP,
роли vs поведение. Показывает не только находки, но и что
из них не сходится — пивоты, ARP-spoof, domain-fronting,
протокольные туннели.

Задача: аналитик получает не плоский список из 500 flows,
а структурированный профиль хостов, набор findings и — главное —
список несогласованностей, которые указывают на скрытые
сценарии: хост, который одновременно жертва и атакующий (pivot);
IP, отвечающий двумя MAC (ARP-spoof); SNI, не совпадающий с
Host (domain fronting).

Работает оффлайн. Никаких внешних API — только локальный разбор.

Чем отличается от других
Zeek, Arkime, tshark, Rita — сотни инструментов парсят pcap
и находят то же самое: DNS-запросы, TLS-хендшейки, HTTP.
Никто из них не проверяет согласованность между слоями данных.

pcap-triage строит из pcap атомарные факты о мире:

text
(192.168.1.12, victim_of, 10.0.1.50, ts, "finding", 0.85)
(192.168.1.12, attacker_of, 192.168.1.1, ts, "finding", 0.80)
(192.168.1.5, has_mac, 00:60:6e:00:9d:f9, ts, "arp", 0.9)
(192.168.1.5, has_mac, aa:bb:cc:dd:ee:02, ts, "arp", 0.6)
И ищет противоречия: два MAC на одном IP (ARP-spoof), два
противоположных утверждения о роли хоста (pivot), SNI ≠ Host
(domain fronting). Это новый слой анализа, поверх findings
и поверх entities.

Что делает
Из одного pcap-файла:

Профиль жертвы. IP, MAC, hostname, username, realm — из
ARP, NBNS, Kerberos. Собирается автоматически.

C2-инфраструктура. DGA, cloud tunnels, typosquatting,
IP-check сервисы, SNI без DNS, известные malware-JA3.

C2-beaconing. Периодические heartbeat-соединения
(jitter < 0.1, ≥ 20 обращений, ≥ 10 минут) + multi-tenant
filter против CDN.

DNS tunneling. Длинные уникальные поддомены под одним
базовым доменом.

Активная разведка. Web-сканеры, port-сканеры, FTP-брутфорс.

Lateral movement. WinRM, PsExec, SMB, RDP между внутренними
хостами.

Эксфильтрация. Large transfers (100 МБ+) и reverse
asymmetry (10:1 при объёме ≥ 1 МБ).

Payload download. Скрипты (.ps1, .sh, .vbs, .hta),
бинарники из HTTP-ответов. Metadata-only, тело на диск не
пишется.

RCE в HTTP. Command injection в URI и POST body
(io.popen, system(), subprocess…) — на полных HTTP-объектах
после TCP reassembly.

Роли хостов. domain_controller, victim_candidate,
attacker_candidate, c2_candidate, gateway_candidate,
pivot.

Противоречия. 7 правил, см. секцию ниже.

GUI. PySide6, 5 вкладок. Отдельный пакет
pcap_triage_gui/, собран в .exe через PyInstaller.

Противоречия (ContradictionDetector)
Новый слой анализа поверх findings. Не детекторы атак, а поиск
несогласованностей между источниками: одно утверждение о мире
подтверждается одним источником и опровергается другим.

Правило	Severity	Что находит
victim_makes_attack	critical	Хост одновременно жертва и атакующий → pivot
mac_ip_conflict	critical	ARP-spoof: два MAC на одном IP
sni_host_mismatch	high	Domain fronting: SNI ≠ HTTP Host
ja3_ua_mismatch	high	JA3 tool + browser UA → мимикрия скрипта
reverse_asymmetry	medium	Пропорция сессии 10:1 (эксфильтрация)
port_service_mismatch	high	TLS на 22, HTTP на 445 → туннель
direct_ip_no_dns	medium	Клиент ходит на IP без DNS-резолва
На CyberCampTask pivot-правило находит 192.168.1.12 — хост,
которого сначала атакуют (brute_force), а затем он сам атакует
(lateral movement на шлюз). Классический сценарий компромисса.

Быстрый старт
powershell
# Установка (один раз)
pip install -e .

# Запуск CLI
python -m pcap_triage capture.pcap

# Запуск GUI
python -m pcap_triage_gui
Отчёт появится в reports/capture_pcap.report.json и
reports/capture_pcap.report.md.

Без аргументов — спросит путь интерактивно:

text
python -m pcap_triage
text
packets:            627694
unique DNS queries: 117
NXDOMAIN count:     0
flows:              2328
findings:           7
report JSON:        reports\CyberCampTask_pcap.report.json
report Markdown:    reports\CyberCampTask_pcap.report.md
Противоречия (1)
🔴 victim_makes_attack — 192.168.1.12 (0.80)

192.168.1.12 сначала атакован (10.0.1.50, ts=1754924349.1),
потом сам атакует (192.168.1.1, ts=1754924987.7).
Классический pivot — проверить сессии 192.168.1.12.

Факты:

victim_of ← 10.0.1.50 [brute_force] (source=finding, conf=0.85)

attacker_of ← 192.168.1.1 [lateral_movement] (source=finding, conf=0.80)

Вероятные причины:

Хост скомпрометирован: сначала атакован, потом сам атакует

Authorized scanner в сети

NAT/proxy: одна IP скрывает несколько хостов

FP одной из эвристик

В сущностях этот хост получает роль pivot поверх
victim_candidate.

Производительность
334 МБ pcap (627k пакетов) — 19 секунд

152 МБ pcap (232k пакетов, с TCP reassembly) — 12 секунд

9.5M пакетов (58 файлов, 4.7 ГБ) — 10 минут полный батч

Память — 106 МБ на 334 МБ файл

В основе — собственный парсер пакетов на struct.unpack,
без scapy dissect. Это даёт 39x ускорение против чистого
scapy. Scapy используется точечно — только для сложных payload.

Что внутри
Экстракторы (8)
Слой	Модуль	Что извлекает
L0	flow.py	5-tuple, байты, timestamps, инициатор
L0	dns.py	DNS-запросы, NXDOMAIN, по источнику
L0	tls.py	SNI + JA3/JA3S из ClientHello/ServerHello
L0	http.py	Host, URI, Method, User-Agent
L0	host_identity.py	MAC из ARP
L0	arp_history.py	История MAC на IP (для ARP-spoof)
L0	nbns.py	Hostname из NBNS (NetBIOS)
L0	kerberos.py	Username, realm, sname из Kerberos
Плюс пост-обработка: reassembler.py — склейка TCP-сегментов,
http_object.py — полные HTTP запросы/ответы из потока,
file_carve.py — метаданные payload'ов (sha256, MIME,
первые 64 байта).

Детекторы (17)
C2 / инфраструктура: dga, cloud_tunnel,
ip_check_service, typosquatting, sni_mismatch,
suspicious_port, ja3_malware.

Активность: port_scan, web_scanner (в vulnerable_path),
brute_force, ftp_brute_force.

Коммуникации: beaconing, dns_tunneling,
lateral_movement, large_transfer.

Payload: vulnerable_path (уязвимые пути + скачивание
скриптов), command_injection (RCE в URI и POST body).

Meta: nxdomain_burst.

Каждый детектор пишет универсальные поля в evidence:
src_ip, dst_ip, dst_port, first_seen, last_seen.

Правила ContradictionDetector (7)
victim_makes_attack, mac_ip_conflict, sni_host_mismatch,
ja3_ua_mismatch, reverse_asymmetry, port_service_mismatch,
direct_ip_no_dns. Реализованы как реестр.

Reporters (3)
JSON — с schema_version, provenance (sha256 pcap),
contradictions, для SIEM.

Markdown — для копирования в тикет или вики. TL;DR
в порядке kill-chain, PIVOT первым.

Flow report — conn.log-стиль, для ручного пивота
в Wireshark.

Enrichment (опционально)
Threat Intel — по флагу --enrich. Shodan InternetDB (без ключа),
AbuseIPDB (нужен ABUSEIPDB_API_KEY), SQLite-кэш с TTL 7 дней.
Не работает в оффлайн-режиме.

GUI
PySide6, 5 вкладок: Прогон / Обогащение / Настройки / История /
Развитие. Тёмная тема, drop zone для pcap, summary grid,
Observations, Highlights, Contradictions, Findings с модалами.
Собран в .exe через PyInstaller (onedir, без UPX).

Архитектура
text
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
в MODULES.md. История версий — в CHANGELOG.md.

Тесты
powershell
pytest tests/ -q
302 теста в 25 файлах. Всё зелёное.

Группа	Файлов	Что покрывает
Парсеры	1	TLS ClientHello (test_tls_parse.py, 10)
Экстракторы	2	HTTP (8), TLS (6)
HTTPObject / JA3	2	test_http_object.py (12), test_ja3.py (8)
Reassembly	1	test_reassembler.py (9)
Детекторы (базовые)	3	test_detectors.py (41), test_beaconing.py (31), test_brute_force.py (9)
Детекторы (0.6.0)	3	test_command_injection.py (10), test_dns_tunneling.py (9), test_file_carve.py (9)
Contradictions	7	по 5 тестов на правило × 7 правил
Агрегаторы	1	test_aggregators_entities.py (10)
Enrichment	4	cache (9), shodan (11), abuseipdb (7), pipeline (4)
Регрессии	1	test_regressions.py (42)
Проверено на
FIRST-2015 Hands-on Network Forensics — 58 pcap'ов,
9.5M пакетов, 4.7 ГБ, полный батч за 10 минут. 386 findings,
11 contradictions, 0 ошибок. Топ findings: nxdomain_burst 93,
sni_without_dns 73, script_download 50, vulnerable_path 46,
command_injection 33.

CTF CyberCampTask (334 МБ, 627k пакетов) — HTTP-брутфорс +
FTP-брутфорс + скачивание скриптов + WinRM lateral movement +
large transfer на rtbcdn.ru. 7 findings, 2 contradictions,
0 FP. Pivot-правило находит 192.168.1.12.

MTA 2025-06-13 — упражнение malware-traffic-analysis.net.
Профиль жертвы 5 из 5 (IP, MAC, hostname, username, realm).

Требования
Python 3.11+

scapy ≥ 2.5 (только для DNS payload + fallback pcapng)

pyyaml ≥ 6.0

PySide6 (только для GUI)

Windows / Linux / macOS. Разрабатывалось под Windows.

Roadmap
0.7.0 (текущая) — ContradictionDetector, 7 правил, GUI v0.1,
302 теста.

0.8.0 — расширение видимости:

DNS-ответы (A/AAAA/CNAME) — для sni_host_mismatch v2 и
direct_ip_no_dns v2.

TLS-сертификаты (CN, SAN) — для cert_cn_sni_mismatch,
self_signed_on_external.

Универсальный контракт Finding (top-level src_ip, dst_ip,
severity, mitre_id).

Timeline / kill-chain reconstruction.

0.9.0 — новые экстракторы:

SMB2, DHCP, SSH-баннер, SMTP.

HTTP/2 framing.

IPv6 в парсере.

1.0.0 — стабильный API:

STIX 2.1 экспорт IOC.

REST API + Web UI.

Плагины (пользовательские правила contradictions).

Структура репозитория
text
pcap_triage/            # ядро
├── extractors/         # 8 экстракторов + post-extract
├── detectors/          # 17 детекторов + mitre_map
├── contradictions/     # 7 правил + факты + реестр
├── aggregators/        # entities + роли + pivot
├── integrations/       # Threat Intel (опционально)
└── reporters/          # JSON, Markdown, flow report

pcap_triage_gui/        # GUI (PySide6)
├── views/              # 5 вкладок
├── widgets/            # переиспользуемые компоненты
├── dialogs/            # модалы
└── workers/            # QThread-обёртки

tests/                  # 302 теста, 25 файлов

tools/                  # dev-скрипты (не часть пакета)
Вклад
Issues и pull requests — приветствуются. Что нужно знать:

Стиль кода — ruff check + ruff format.

Тесты — обязательны для новых правил и детекторов.

Комментарии — на русском, объясняют «почему», не «что».

Лицензия
MIT. См. LICENSE (если файл отсутствует — будет добавлен
перед публикацией).

Коммит
powershell
git add README.md
git commit -m "docs(README): переписать под v0.7.0"
git log --oneline -3