# Paradox

[![test](https://github.com/v314xm/paradox/actions/workflows/test.yml/badge.svg)](https://github.com/v314xm/paradox/actions/workflows/test.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**PCAP triage: 20 детекторов, 12 правил противоречий, GUI, 933 теста.**

Инструмент для оффлайн-разбора pcap. Ищет **противоречия между слоями данных** — DNS vs SNI, JA3 vs User-Agent, MAC vs IP, роли vs поведение. Показывает не только findings, но и то, что из них не сходится: pivot-хосты, ARP-spoof, domain-fronting, протокольные туннели.

![Paradox GUI](docs/screenshot.png)

## Чем отличается

Zeek, Arkime, tshark, Rita — сотни инструментов парсят pcap и находят то же: DNS-запросы, TLS-хендшейки, HTTP. **Никто не проверяет согласованность между слоями.**

Paradox строит из pcap атомарные факты о мире:
(192.168.1.12, victim_of, 10.0.1.50, ts, 0.85)
(192.168.1.12, attacker_of, 192.168.1.1, ts, 0.80) ← pivot
(192.168.1.5, has_mac, 00:60:6e:00:9d:f9, ts, 0.90)
(192.168.1.5, has_mac, aa:bb:cc:dd:ee:02, ts, 0.60) ← ARP-spoof

text

И ищет противоречия. Это новый слой анализа — поверх findings и поверх entities.

## Быстрый старт

```bash
pip install -e ".[gui]"

paradox capture.pcap          # CLI → JSON + Markdown
python -m paradox_gui         # GUI
Python 3.11+. Windows / Linux / macOS.

Готовый .exe — в Releases.

Пример вывода
text
packets:            627 694
unique DNS queries: 117
NXDOMAIN count:     0
flows:              2 328
findings:           7
contradictions:     2
report JSON:        reports/CyberCampTask.report.json
report Markdown:    reports/CyberCampTask.report.md
В Markdown — TL;DR в порядке kill-chain:

PIVOT: 192.168.1.12 (жертва brute_force, но сама атакует 192.168.1.1 через WinRM).
Payload: /ftp_update.sh (sh, 4 KB, sha256 a1b2c3…).
Timeline: port_scan → ftp_brute_force → command_injection → beaconing → large_transfer.

Что делает
Из одного pcap:

Профиль жертвы. IP, MAC, hostname, username, realm — из ARP, DHCP, NBNS, Kerberos.

C2-инфраструктура. DGA, cloud tunnels, typosquatting, IP-check сервисы, SNI без DNS, malware-JA3.

C2-beaconing. Периодические heartbeat-соединения (jitter < 0.1, ≥ 20 обращений, ≥ 10 минут) + multi-tenant filter против CDN.

DNS tunneling. Длинные уникальные поддомены под одним базовым доменом.

Активная разведка. Web/port-сканеры, SSH/FTP-брутфорс.

Lateral movement. WinRM, PsExec, SMB, RDP между внутренними хостами.

Эксфильтрация. Large transfers (100 МБ+) + reverse asymmetry (10:1 при объёме ≥ 1 МБ).

Payload download. Скрипты, бинарники из HTTP. Metadata-only, тело на диск не пишется.

RCE в HTTP. Command injection в URI и POST body на полных HTTP-объектах после TCP reassembly.

YARA. Сканирование вырезанных файлов пользовательскими правилами.

Роли хостов. domain_controller, victim_candidate, attacker_candidate, c2_candidate, gateway_candidate, pivot.

Timeline / kill-chain. Хронология findings и противоречий по фазам (recon → initial_access → execution → lateral_movement → c2 → exfiltration).

Противоречия (12 правил)
Правило	Severity	Что находит
victim_makes_attack	critical	Хост одновременно жертва и атакующий → pivot
mac_ip_conflict	critical	ARP-spoof: два MAC на одном IP
sni_host_mismatch	high	Domain fronting: SNI ≠ HTTP Host
ja3_ua_mismatch	high	JA3 tool + browser UA → мимикрия скрипта
port_service_mismatch	high	TLS на 22, HTTP на 445 → туннель
reverse_asymmetry	medium	Пропорция сессии 10:1 (эксфильтрация)
direct_ip_no_dns	medium	Клиент ходит на IP без DNS-резолва
sni_without_dns	medium	SNI без DNS-ответа в захвате
dns_answer_mismatch	medium	SNI не совпадает с резолвнутым IP (CNAME-aware)
sni_cert_mismatch	medium	SNI ≠ CN/SAN сертификата
self_signed_cert	medium	Самоподписанный сертификат на внешнем ресурсе
expired_cert	low	Просроченный сертификат
GUI
8 вкладок: Прогон / История / Обогащение / Настройки / IPv6 / Таймлайн / Экспорт / Сравнение.

Прогон — drop zone, прогресс по фазам, summary, findings с фильтрами, противоречия, «Граф связей», «Файлы» (carved), What-If (исключить IP/домен → пересчитать).

История — все прогоны сессии, клик → детали.

Обогащение — Threat Intel по выбранным IOC.

Настройки — 11 секций Config с тултипами, профили (Default/CTF/Corporate), отключение детекторов и правил.

IPv6 — NDP-соседи, роутеры.

Таймлайн — kill-chain фазы с фильтрами.

Экспорт — CSV findings + STIX 2.1 bundle.

Сравнение (B1) — два JSON-отчёта → что добавилось / исчезло / изменилось. Для повторного триажа одного и того же pcap через день/неделю.

Сравнение прогонов (B1)
text
$ paradox FIN-2015.pcap                    # вчера
$ paradox FIN-2015.pcap                    # сегодня
GUI → «Сравнение» → загрузить old.json + new.json:

text
Findings: +2 −1 ~0 · Противоречий: +1 −0 · packets: 100→150 (+50)

  Новые findings (2)
    beaconing           10.0.0.5 → 1.2.3.4:443
    ja3_malware         Cobalt Strike (ja3=a0e9f5d6…)
  Исчезли findings (1)
    dga_domain          xk7f2n9p.com
  Новые противоречия (1)
    victim_makes_attack 192.168.1.12  critical
CLI
bash
paradox capture.pcap                          # JSON + Markdown в reports/
paradox capture.pcap -o reports/today.json    # конкретный путь
paradox capture.pcap --enrich                 # + Threat Intel
paradox capture.pcap -o reports/              # директория
Выход:

reports/<pcap>.report.json — полный отчёт (schema_version, provenance, contradictions)

reports/<pcap>.report.md — TL;DR, timeline, findings, IOC

reports/iocs.txt iocs.csv iocs.json suricata.rules queries.txt — IOC-экспорт

Производительность
Размер	Пакетов	Время
152 МБ	232k	12 сек (с TCP reassembly)
334 МБ	627k	19 сек
4.7 ГБ (58 файлов)	9.5M	10 мин полный батч
Память — ~106 МБ на 334 МБ файл.

В основе — собственный парсер пакетов на struct.unpack, без scapy dissect. 39× ускорение против чистого scapy. Scapy используется точечно — только для сложных payload.

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
                             Timeline / kill-chain
                                            ↓
                                 build_entities
                                  (роль pivot)
                                            ↓
                            Reporters → JSON + MD + IOC
Timeline строится после contradictions (нужны оба источника), до build_entities (pivot — это «жертва + атакующий», роль вычисляется по contradictions).

Что внутри
Слой	Модуль	Кол-во
Extractors	flow, dns, tls, http, host_identity, arp_history, dhcp, nbns, kerberos, ndp, ssh_banner, smtp	12
Post-extract	reassembler, http_object, tls_cert, file_carve	4
Detectors	DGA, port_scan, suspicious_port, nxdomain_burst, cloud_tunnel, ip_check_service, typosquatting, sni_mismatch, ja3_malware, brute_force, ftp_brute_force, ssh_brute_force, smtp_spam, beaconing, dns_tunneling, lateral_movement, large_transfer, vulnerable_path, command_injection, yara	20
Contradictions	см. таблицу выше	12
Analyzers	absence, counterfactual (What-If), story, ndp	4
Reporters	JSON, Markdown, flow report, IOC (txt/csv/json/suricata/kql)	4
Enrichment (опционально)	Shodan InternetDB, AbuseIPDB, VirusTotal, GreyNoise, AlienVault OTX, URLScan, URLhaus, MalwareBazaar, ThreatFox	9
MITRE ATT&CK маппинг для всех findings.

Тесты
bash
pytest -m "not slow"           # ~20 сек, 933 passed
ruff check .                   # 0 ошибок
933 теста в ~45 файлах. CI на GitHub Actions прогоняет 6 комбинаций: ubuntu/windows/macos × Python 3.11/3.12/3.13.

Покрытие:

Парсеры (TLS, X.509 DER, Kerberos, NBNS, HTTP, IPv6)

Все 12 extractors

Все 20 детекторов + MITRE-map

Все 12 правил contradictions

Reassembler, HTTPObject, JA3/JA3S, YARA

Регрессионные тесты на реальные FP (test_regressions.py, 42 теста)

B1 diff (test_run_diff.py, 10 тестов)

Config, GUI smoke-тесты

Проверено на
FIRST-2015 Hands-on Network Forensics — 58 pcap, 9.5M пакетов, 4.7 ГБ, 10 минут. 386 findings, 11 contradictions, 0 ошибок.

CTF CyberCampTask — 334 МБ, 627k пакетов. 7 findings, 2 contradictions, 0 FP. Pivot-правило находит 192.168.1.12.

MTA 2025-06-13 — malware-traffic-analysis.net. Профиль жертвы 5/5 (IP, MAC, hostname, username, realm).

Установка
bash
# Разработка с GUI
pip install -e ".[dev,gui]"

# + YARA + Threat Intel
pip install -e ".[dev,gui,yara,enrich]"

# Pre-commit (один раз)
pre-commit install
Конфигурация
Всё через Config (frozen dataclass) или через GUI «Настройки»:

Пороги детекторов (beaconing jitter, nxdomain window, port_scan min_dsts)

Allowlist (CDN, DoH, Windows Update)

Отключение детекторов / правил

API-ключи Threat Intel (в keyring, не в JSON)

Профили: Default / CTF (сниженные пороги) / Corporate (шумные детекторы выключены).

Требования
Python 3.11+

scapy ≥ 2.5 (DNS payload + fallback pcapng)

pyyaml ≥ 6.0

PySide6 (только для GUI)

yara-python (опционально, для YARA-правил)

keyring (опционально, для API-ключей Threat Intel)

Roadmap
1.0.0 — 20 детекторов, 12 правил противоречий, GUI (8 вкладок), B1 (сравнение прогонов), 933 теста, CI на 6 комбинациях, .exe через PyInstaller.

1.1.x — улучшения B1 (diff entities, diff timeline, экспорт в Markdown), скриншоты в README.

1.2.x — stream mode для pcap > 2 ГБ, без полной загрузки в RAM.

backlog — SMB relay, DHCP starvation, DoH-аномалии.

Вклад
Issues и pull requests приветствуются.

Стиль кода — ruff check . (0 ошибок обязательно).

Тесты — обязательны для новых правил и детекторов.

Pre-commit — pre-commit install (ruff + trailing whitespace + eof).

Комментарии — на русском, объясняют «почему», не «что».

Лицензия
MIT. См. LICENSE.

text

---

## Что сделать после замены

### 1. Скриншот в `docs/screenshot.png`

Пока его нет — README покажет «сломанную картинку». Два пути:

**A. Быстро снять самому:**

```powershell
python -m paradox_gui
# открыть pcap → дождаться результата → Win+Shift+S
# сохранить в docs/screenshot.png
B. Пока нет скриншота — временно удали строку:

markdown
![Paradox GUI](docs/screenshot.png)
2. Проверить, что LICENSE существует
powershell
Test-Path LICENSE
Если False — создай с текстом MIT (см. мои прошлые ответы или choosealicense.com/licenses/mit).

3. Коммит
powershell
git add README.md docs/screenshot.png LICENSE
git commit -m "docs: README под 1.0.0 — 20 детекторов, 12 правил, 933 теста, B1, скриншот, бейджи"
git push origin master
4. Проверка через 1 минуту
Открой https://github.com/v314xm/paradox — бейдж test должен стать зелёным (если CI зелёный), скриншот отобразится.

5. About в правой колонке репозитория
⚙️ → справа «About» → Edit:

Description: PCAP triage: 20 detectors, 12 contradiction rules, GUI, offline. Finds pivots, ARP-spoof, domain-fronting.

Topics: pcap, network-forensics, dfir, security, triage, incident-response, python, pyside6, mitre-attack, scapy
