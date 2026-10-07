# TODO

## Сделано
- [x] CLI с интерактивным вводом пути
- [x] FlowExtractor + flow report
- [x] DNSExtractor
- [x] 6 детекторов: DGA, SuspiciousPort, NXDOMAINBurst,
      CloudTunnel, IPCheckService, Typosquatting
- [x] 26 unit-тестов (в т.ч. регрессии на DGA с дефисом)
- [x] JSON-отчёт с provenance и sha256
- [x] make_test_pcap.py с синтетикой
- [x] Git + initial snapshot
- [x] Фикс DGA false positive (safebrowsing-cache)
- [x] Фикс имени отчёта (полный stem от pcap)
- [x] Прогон на реальном pcap (FIRST-2015, snort.log.*)

## В работе
- [ ] FlowAggregator: группировка flows по (src_ip, dst_ip, dst_port)
      + статистики (interval_cv, duration_cv, packets_cv, suspicion)
- [ ] BeaconingDetector поверх FlowAggregator
- [ ] Секция flow_groups в JSON + топ-5 в консоли

## Следующее
- [ ] Windowing в CaptureState (для NXDOMAIN burst, FastFlux, объёмного exfil)
- [ ] StreamReassembler (TCP reassembly)
- [ ] TLSExtractor + SNIMismatchDetector
- [ ] HTTPExtractor
- [ ] HTTPObjectExtractor + FileCarve
- [ ] Correlator (entity scoring)
- [ ] Threat Intel enrichment (VT, SQLite-кэш)
- [ ] KerberosExtractor + LDAPExtractor
- [ ] HostIdentityExtractor
- [ ] AD-детекторы (Kerberoasting, DCSync, ADRecon)
- [ ] Timeline correlation
- [ ] IncidentReportReporter + IOCExportReporter
- [ ] Streamlit-обёртка

## Известные долги
- timestamps в FlowStats растут неограниченно → заменить на Welford
- FlowKey не нормализует направление → канонизация для exfiltration
- TLS-парсер ручной → нужен reassembly и JA3
- DGA по энтропии → false positives на CDN, расширять allowlist
- nxdomain_burst считает за весь файл → должен быть по окну