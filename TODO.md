# TODO

## Сделано
- [x] CLI с интерактивным вводом пути
- [x] FlowExtractor + flow report
- [x] DNSExtractor
- [x] 7 детекторов: DGA, SuspiciousPort, NXDOMAINBurst,
      CloudTunnel, IPCheckService, Typosquatting, SNIMismatch
- [x] 62 unit-теста
- [x] JSON-отчёт с provenance и sha256
- [x] make_test_pcap.py с синтетикой
- [x] Git + история коммитов
- [x] Фиксы DGA false positives (safebrowsing, дефис)
- [x] Фикс имени отчёта
- [x] Прогон на реальных pcap (FIRST-2015, CTF 334 МБ)
- [x] SuspiciousPort: игнор приватных dst + агрегация
- [x] Прогресс-бар в парсинге
- [x] Raw parser (struct) + 39x ускорение
- [x] TLSExtractor — SNI из ClientHello (ручной парсер)
- [x] SNIMismatchDetector с суффиксным allowlist
- [x] CTF baseline = 0 findings

## В работе
- [ ] (ничего не начато)

## Следующее (по приоритету)
- [ ] Threat Intel enrichment (VT + SQLite-кэш, rate limit)
      Закрывает класс задач: C2 с читаемым именем, который
      резолвится через DNS (пример: salam-spbsed-*.rtbcdn.ru)
- [ ] FlowAggregator + BeaconingDetector
      Группировка flows по (src_ip, dst_ip, dst_port),
      статистика интервалов, suspicion score
- [ ] Windowing в CaptureState
      Для nxdomain_burst по окну, FastFlux, объёмного exfil
- [ ] Роль хостов в отчёте (жертва/сканер/сервер)
- [ ] Направление трафика (internal→external, download/upload)
- [ ] Malformed packets (счётчик + источник)

## Дальше
- [ ] StreamReassembler (TCP reassembly)
- [ ] HTTPExtractor + HTTPObjectExtractor + FileCarve
- [ ] JA3/JA3S fingerprints
- [ ] Correlator (entity scoring)
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
- IPv6 не поддержан в парсере
- TLS ClientHello без reassembly → ~5% фрагментированных пропущены
- JA3 отсутствует
- nxdomain_burst считает за весь файл → должен быть по окну
- DGA по энтропии → false positives на CDN/Azure,
  растить allowlist по мере поступления
- Malformed packets не считаются