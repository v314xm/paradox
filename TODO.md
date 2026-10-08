# TODO

## Сделано
- [x] CLI с интерактивным вводом пути
- [x] FlowExtractor + flow report
- [x] DNSExtractor
- [x] TLSExtractor — SNI из ClientHello
- [x] HTTPExtractor (из параллельной ветки)
- [x] 9 детекторов:
      DGA, SuspiciousPort, NXDOMAINBurst, CloudTunnel,
      IPCheckService, Typosquatting, SNIMismatch,
      BruteForce, VulnerablePath
- [x] 101 unit-тест
- [x] JSON-отчёт с provenance и sha256
- [x] Markdown-отчёт для тикета
- [x] Entities (internal/external, роли victim/attacker/
      gateway/c2, SNI, DNS, findings_indices)
- [x] Direction summary (uploaded/downloaded/internal)
- [x] HTTP-секция в JSON и Markdown
- [x] make_test_pcap.py
- [x] Git + история коммитов
- [x] Фиксы DGA false positives (safebrowsing, дефис, CDN)
- [x] Фикс имени отчёта
- [x] Прогресс-бар в парсинге
- [x] Raw parser (struct) + 39x ускорение
- [x] Прогоны на 5 реальных pcap:
      CTF CyberCampTask (334 МБ), FIRST-2015 ×3,
      IDS-pcap, MTA 2025-06-13

## В работе
- [ ] (ничего не начато)

## Следующее (по приоритету, из ревью MTA 2025-06-13)
- [ ] **P0. SNI bug** — на MTA pcap для 83.137.149.15:443
      инструмент показал windows.php.net вместо windows-msgs.com.
      Диагностика: логирование SNI в TLSExtractor (timestamp,
      5-tuple, sni), проверка, что берём только первый ClientHello
      именно этого flow. Блокирует доверие к отчёту.
- [ ] **P1. KerberosExtractor** — username, hostname, realm
      (cname, sname, realm, msg_type). Без него профиль жертвы
      неполный.
- [ ] **P2. HostIdentityExtractor** — IP ↔ MAC ↔ hostname
      из ARP, DHCP, NBNS, Kerberos.
- [ ] **P3. Классификация сущностей** — victim vs DC vs attacker.
      Правила: DC = много Kerberos/LDAP/SMB на 88/389/445;
      victim = findings + исходящие на C2;
      attacker = сканирование многих портов по внутренним.
- [ ] **P4. HTTPObjectExtractor** — сохранение тел POST/GET,
      sha256, magic bytes (для VT-проверки).

## Дальше
- [ ] Threat Intel enrichment (VT + SQLite-кэш, rate limit)
- [ ] FlowAggregator + BeaconingDetector
- [ ] Windowing в CaptureState
- [ ] Malformed packets (счётчик + источник)
- [ ] StreamReassembler (TCP reassembly)
- [ ] JA3/JA3S fingerprints
- [ ] Correlator (entity scoring, timeline)
- [ ] LDAPExtractor, AD-детекторы
- [ ] IncidentReportReporter + IOCExportReporter
- [ ] Streamlit-обёртка

## Известные долги
- timestamps в FlowStats растут неограниченно → на 334 МБ
  дают 106 МБ RAM, не срочно (Welford отложен)
- FlowKey не нормализует направление (SessionKey есть, но
  FlowStats не использует)
- IPv6 не поддержан в парсере (только заглушка)
- TLS ClientHello без reassembly → ~5% пропущены
- JA3 отсутствует
- nxdomain_burst считает за весь файл → должен быть по окну
- BruteForceDetector даёт false positive на Google Safe Browsing
  (Firefox качает много разных URI с одного IP) — фикс:
  учитывать ratio unique_uris / flow_count
- DGA по энтропии → false positives на CDN/Azure,
  растить allowlist по мере поступления
- Malformed packets не считаются
- HTTPObjectExtractor отсутствует — нет sha256 файлов