# TODO

## Сделано
- [x] CLI с интерактивным вводом пути
- [x] FlowExtractor + flow report
- [x] DNSExtractor
- [x] 6 детекторов: DGA, SuspiciousPort, NXDOMAINBurst,
      CloudTunnel, IPCheckService, Typosquatting
- [x] 29 unit-тестов
- [x] JSON-отчёт с provenance и sha256
- [x] make_test_pcap.py с синтетикой
- [x] Git + initial snapshot
- [x] Фикс DGA false positive (safebrowsing-cache, дефис в label)
- [x] Фикс имени отчёта (полный stem от pcap)
- [x] Прогон на реальном pcap (FIRST-2015, CTF CyberCampTask 334 МБ)
- [x] SuspiciousPort: игнор приватных dst + агрегация по (dst_ip, dst_port)
- [x] Прогресс-бар в парсинге
- [x] Валидация против ручного разбора (IP, объёмы, SSH — совпадают)

## В работе
- [ ] Оптимизация скорости парсинга (профилирование → решение)
- [ ] Фиксы false positives на CTF: cloudapp.azure.com, msedge.net, .local

## Следующее (по приоритету)
- [ ] Роль хостов в отчёте (жертва/сканер/сервер)
- [ ] Направление трафика (internal→external, download/upload)
- [ ] Malformed packets (счётчик + источник)
- [ ] TLS SNI (простой вариант — ClientHello в одном сегменте)
- [ ] FlowAggregator + BeaconingDetector
- [ ] Windowing (NXDOMAIN burst по окну, FastFlux)
- [ ] StreamReassembler
- [ ] HTTPExtractor + HTTPObjectExtractor
- [ ] Correlator (entity scoring)
- [ ] Threat Intel enrichment (VT, SQLite-кэш)
- [ ] KerberosExtractor + LDAPExtractor
- [ ] HostIdentityExtractor
- [ ] AD-детекторы (Kerberoasting, DCSync, ADRecon)
- [ ] Timeline correlation
- [ ] IncidentReportReporter + IOCExportReporter
- [ ] Streamlit-обёртка

## Известные долги
- timestamps в FlowStats растут неограниченно → но на 334 МБ
  дают всего 106 МБ RAM, не срочно (Welford отложен)
- FlowKey не нормализует направление → нужно для exfiltration
- DGA по энтропии → false positives на CDN/Azure, растить allowlist
- nxdomain_burst считает за весь файл → должен быть по окну
- Скорость парсинга ~3.5 МБ/с → цель 15-30 МБ/с (dpkt или raw)