# tools/

Dev-скрипты. Не часть пакета `pcap_triage/`, не импортируются
ядром и GUI. Запускаются вручную из корня репозитория.

Зависимости — те же, что у проекта: `pip install -e .`

## Диагностика

- `diagnose.py` — проверяет наличие C2-доменов в `dns_queries`.
  Запускается отдельно от pipeline, читает pcap сам.
  Полезен при отладке DGA/cloud_tunnel на новом датасете.

- `portscan_check.py` — считает `dst_port` с одного `src_ip`
  к одному `dst_ip`. Помогает отличить horizontal scan
  от обычного серфинга.

- `ssh_check.py` — все flows на порт 22 с разбивкой per `src_ip`.
  Отличает brute-force (много коротких flows) от одной
  длинной сессии и от port-скана.

- `diag_nbns.py` — разовый разбор NBNS-пакетов. Проверяет,
  что `NBNSExtractor` извлекает hostname корректно.

- `diag_kerberos.py` — разовый разбор Kerberos AS-REQ/AS-REP.
  Проверяет извлечение `cname`, `crealm`, `sname`.

## Батч-прогоны

- `batch_analyze.py` — массовый прогон `run_pipeline` по всем
  pcap из папки (FIRST-2015 и аналоги). Ищет `.pcap`, `.pcapng`,
  `.cap`, `snort.log.*` рекурсивно. Сохраняет `batch_results.json`
  и `reports_batch/<name>.json`. Результаты пишутся после каждого
  файла — можно прервать Ctrl+C.

## Синтетика для тестов

- `make_test_pcap.py` — генератор синтетического pcap
  с заданными flows/DNS/TLS. Используется для ручной проверки
  детекторов на контролируемом примере.

## Запуск

Из корня репозитория:

```powershell
python tools/diagnose.py path\to\capture.pcap
python tools/batch_analyze.py D:\datasets\FIRST-2015
python tools/make_test_pcap.py

