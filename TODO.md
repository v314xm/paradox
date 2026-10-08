# TODO

## Сделано
- [x] CLI с интерактивным вводом пути
- [x] FlowExtractor + flow report
- [x] DNSExtractor
- [x] TLSExtractor — SNI из ClientHello (ручной парсер)
- [x] HTTPExtractor (Host, UA, URI, Method)
- [x] 9 детекторов: DGA, SuspiciousPort, NXDOMAINBurst,
      CloudTunnel, IPCheckService, Typosquatting,
      SNIMismatch, BruteForce, VulnerablePath
- [x] 101 unit-тест
- [x] JSON-отчёт с provenance и sha256
- [x] Markdown-отчёт для тикета
- [x] Entities с ролями (internal/external, victim_candidate,
      attacker_candidate, gateway_candidate, c2_candidate)
- [x] Direction summary (uploaded/downloaded/internal)
- [x] HTTP-секция в JSON и Markdown
- [x] make_test_pcap.py
- [x] Git + история коммитов
- [x] Фиксы DGA false positives (safebrowsing, дефис, CDN)
- [x] Фикс имени отчёта
- [x] Прогресс-бар в парсинге
- [x] Raw parser (struct) + 39x ускорение
- [x] Автоопределение pcap / pcapng (fallback на scapy PcapReader)
- [x] Прогоны на 6 реальных pcap:
      CTF CyberCampTask (334 МБ), FIRST-2015 ×3,
      IDS-пакет (WordPress), MTA 2025-06-13,
      сканер уязвимостей (78.153.140.203)
- [x] Роли attacker_candidate / victim_candidate для
      vulnerable_path и script_download
- [x] P0 SNI — проверен на MTA 2025-06-13, совпадает
      с Wireshark (windows.php.net), false positive ревьюера
      (спутал Host HTTP с SNI TLS)

## В работе
- [ ] (ничего не начато)

## Следующее (по приоритету, C → B → A)

### C. Классификация DC vs victim vs attacker (30-60 мин)
- [ ] Роль `domain_controller` для internal:
      много Kerberos (порт 88) / LDAP (389) / SMB (445)
      от **разных** внутренних хостов.
- [ ] Роль `victim` не должна смешиваться с `gateway_candidate`.
- [ ] На MTA pcap: 10.6.13.3 → domain_controller,
      10.6.13.133 → victim (сейчас помечен attacker_candidate).
- [ ] Тесты: DC с 100+ Kerberos-запросов от 5+ хостов.
- [ ] Тесты: обычный хост с 3 Kerberos от 1 хоста — не DC.

### B. HostIdentityExtractor (1.5-2 часа)
- [ ] ARPExtractor: парсинг ARP-запросов/ответов из PacketRecord
      (поля уже есть — `arp_sender_mac`, `arp_sender_ip`,
      `arp_target_mac`, `arp_target_ip`).
- [ ] NBNSExtractor: имя хоста из NBNS-запросов.
- [ ] DHCPExtractor: hostname из DHCP Option 12.
- [ ] `HostIdentity` в CaptureState: `ip ↔ mac ↔ hostname`.
- [ ] Entity.mac / Entity.hostname заполняются автоматически.
- [ ] На MTA pcap: 10.6.13.133 → MAC 24:77:03:ac:97:df.
- [ ] Тесты: ARP-запрос → binding, DHCP hostname → binding,
      конфликт IP-MAC разрешается по приоритету.

### A. KerberosExtractor (2-3 часа)
- [ ] Парсер Kerberos: AS-REQ (type 10), AS-REP (11),
      TGS-REQ (12), TGS-REP (13), AP-REQ (14).
- [ ] Поля: cname, sname, realm, msg_type.
- [ ] cname без `$` → user, cname с `$` → host.
- [ ] `state.kerberos_users: set[str]`
- [ ] `state.kerberos_hosts: set[str]`
- [ ] `state.kerberos_realms: set[str]`
- [ ] Entity.username / Entity.realm заполняются по IP клиента.
- [ ] На MTA pcap: rgaines, DESKTOP-5AVE44C, MASSFRICTION.COM.
- [ ] Тесты: AS-REQ, TGS-REQ, AP-REQ из hex-дампов.

## Дальше
- [ ] HTTPObjectExtractor — сохранение тел POST/GET,
      sha256, magic bytes (для VT-проверки)
- [ ] BruteForceDetector — ratio unique_uris / flow_count
      (устранить false positive на Google Safe Browsing)
- [ ] Threat Intel enrichment (VT + SQLite-кэш, rate limit)
- [ ] FlowAggregator + BeaconingDetector
- [ ] Windowing в CaptureState
- [ ] Malformed packets (счётчик + источник)
- [ ] StreamReassembler (TCP reassembly)
- [ ] JA3/JA3S fingerprints
- [ ] Correlator (entity scoring, timeline)
- [ ] LDAPExtractor, AD-детекторы
- [ ] IncidentReportReporter + IOCExportReporter
- [ ] Streamlit-обёртка / FastAPI бэкенд

## Известные долги
- timestamps в FlowStats растут неограниченно → на 334 МБ
  дают 106 МБ RAM, не срочно (Welford отложен)
- FlowKey не нормализует направление (SessionKey есть,
  но FlowStats не использует)
- IPv6 не поддержан в парсере (только заглушка)
- TLS ClientHello без reassembly → ~5% фрагментированных
  пропущены
- JA3 отсутствует
- nxdomain_burst считает за весь файл → должен быть по окну
- BruteForceDetector false positive на Google Safe Browsing
- DGA по энтропии → false positives на CDN/Azure,
  растить allowlist по мере поступления
- Malformed packets не считаются
- HTTPObjectExtractor отсутствует — нет sha256 файлов
- Kerberos/HostIdentity отсутствуют — профиль жертвы неполный