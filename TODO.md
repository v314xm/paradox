# TODO

## Сделано
- [x] CLI с интерактивным вводом пути
- [x] FlowExtractor + flow report
- [x] DNSExtractor
- [x] 6 детекторов: DGA, SuspiciousPort, NXDOMAINBurst,
      CloudTunnel, IPCheckService, Typosquatting
- [x] 24 unit-теста
- [x] JSON-отчёт с provenance и sha256
- [x] make_test_pcap.py с синтетикой

## В работе
- [ ] Windowing в CaptureState (нужно для beaconing)
- [ ] BeaconingDetector

## Следующее
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