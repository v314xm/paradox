# Paradox: публикация и первые пользователи

Рабочий документ, не для публикации как есть. Состояние на 2026-11-13:
репозиторий `v314xm/paradox`, 0 звёзд, 0 форков, 5 скачиваний ассетов
(1.9.0 и 1.8.0 вышли 13 ноября, 1.7.0 — двумя днями раньше). Причина
нулевой воронки — не качество, а отсутствие дистрибуции: репозиторий
нигде не объявлен.

Порядок важен: сначала упаковка (1–2), потом один пост (3–4). Пост в пустой
репозиторий без GIF и английского README сжигает единственный шанс на
первое впечатление.

---

## 1. GitHub: 15 минут

**Description** (About, до 350 символов):

```text
Offline PCAP triage with a contradiction layer: 30 detectors, 13 cross-source
rules (DNS vs SNI, JA3 vs UA, MAC vs IP, role vs behaviour), CLI + GUI. MIT.
```

**Topics** (Settings → Topics, лимит GitHub — 20, вставлять без `#`, по одному):

```text
pcap  pcap-analysis  packet-analysis  network-forensics  dfir
incident-response  threat-hunting  malware-analysis  blue-team  c2-detection
network-security  network-analysis  traffic-analysis  wireshark  security-tools
soc  forensics  triage  pyside6  python
```

**Social preview** (Settings → Social preview, 1280×640): тёмный фон,
логотип, надпись «Paradox — PCAP triage with contradictions», строка
«30 detectors · 13 rules · 1656 tests». Без мелкого текста — превью
показывается в лентах размером с открытку.

Проверить: `https://github.com/v314xm/paradox` открывается без логина,
README виден целиком, вверху есть переключатель `Русский · English`.

**Release notes 1.9.0** — переписать из CHANGELOG в 5 строк: что нового,
чем полезно, что скачать. Первая строка должна читаться в списке релизов.

---

## 2. Демо-GIF: 1–2 часа

Гифка на первом экране README продаёт лучше трёх экранов текста. Снимать
только на публичном захвате (malware-traffic-analysis.net), без реальных
адресов и учёток.

| Время | Экран | Что происходит |
|---|---|---|
| 0.0–1.0 с | пустое окно «Прогон» | курсор перетаскивает `2025-06-13-traffic.pcap` в drop zone |
| 1.0–2.0 с | прогресс | фазы разбора сменяются, счётчик пакетов растёт |
| 2.0–4.0 с | результаты | плитки итога: находки по severity, противоречия, файлы, TLS |
| 4.0–6.0 с | «Что привлекло внимание» | курсор открывает карточку противоречия |
| 6.0–8.0 с | окно «Объяснение» | текст «что произошло / почему важно / что дальше» |
| 8.0–9.5 с | «Код инжекта» | подсветка sink, цепочка декодирования |
| 9.5–10.0 с | логотип + `paradoxtool.ru` | финальный кадр |

Настройки записи: 1280×720, 12–15 fps, без курсора-хайлайта, паузы не
дольше 0.5 с. Инструменты: ShareX (Windows), ScreenToGif, OBS; сжатие —
`gifski --fps 15 --width 1280`. Цель — **до 8 МБ**, иначе GitHub грузит
гифку рывками.

Файл: `docs/assets/demo.gif`. Вставить в оба README сразу после вводного
абзаца:

```markdown
![Paradox demo](docs/assets/demo.gif)
```

Пока гифки нет — оставить `docs/assets/main.png`, но не ссылаться на
несуществующий файл.

---

## 3. Habr: длинный пост (RU)

Заголовок (выбрать один):

- «Paradox: триаж pcap, который ищет не находки, а противоречия»
- «Разобрать 627 тысяч пакетов за 14 секунд и найти pivot-хост»
- «Я написал инструмент, который ловит ложь между слоями pcap»

Теги: Информационная безопасность, Python, Сети, Открытый исходный код.
Хабы: «Информационная безопасность», «Python», «Системное администрирование».

---

**Текст:**

Есть тип задач, который не любят все: приносят pcap на 300–600 МБ и просят
«посмотреть, что тут». Wireshark открывает файл, Zeek пишет conn.log, Suricata
сыплет алертами. Через час у тебя есть список событий и ни одного ответа на
главный вопрос — **кто здесь атакует, а кто жертва**.

Я начал с простого наблюдения: в реальном инциденте данные почти всегда
противоречат друг другу. DNS говорит, что хост пошёл на `cdn-update.com`,
SNI — что на `45.13.…`, сертификат — что это самоподпись, а JA3 — что клиент
не браузер, а скрипт. Каждый факт по отдельности — шум. Вместе они складываются
в картину, и её видно без экспертизы уровня «посидеть три дня».

Так появился Paradox — оффлайн-инструмент триажа pcap. Он не заменяет
Wireshark и Zeek: он отвечает на вопрос «что здесь не сходится» и показывает
это на одном экране.

**Что внутри**

Конвейер из шести слоёв, каждый — реестр: 12 экстракторов, 30 детекторов,
13 правил противоречий, timeline, граф атаки, отчёты.

Противоречия — главное. Правило не ищет атаку, оно ищет несогласованность
между источниками:

- DNS vs SNI — домен резолвится в один IP, а TLS идёт на другой;
- JA3 vs User-Agent — браузерный UA при JA3 известного инструмента;
- MAC vs IP — два MAC на одном адресе (ARP-spoof);
- роль vs поведение — рабочая станция по OUI неожиданно отдаёт HTTP-сервер;
- жертва vs атакующий — хост, который сам атакует, — это pivot.

Последнее правило — самое полезное. На учебном захвате CyberCampTask
получается цепочка: `port_scan → ftp_brute_force → command_injection →
beaconing → large_transfer`, а `192.168.1.12` одновременно жертва брутфорса
и источник атак через WinRM. Это и есть ответ, который обычно ищут руками.

**Как выглядит работа**

```text
paradox capture.pcap          # JSON + Markdown в reports/
python -m paradox_gui         # GUI: 9 вкладок
```

334 МБ и 627 694 пакета разбираются за 14,4 секунды на одном ядре. Ускорение
дали не отчёты, а пакетный цикл: свой читатель pcap, `struct.unpack` вместо
scapy-dissect, `slots` у записи пакета и быстрый выход на чистых ACK.

В отчёте — не только таблица находок. У каждой находки и каждого
противоречия есть объяснение человеческим языком: что произошло, почему это
важно, куда смотреть дальше и где детектор может ошибаться. Один и тот же
текст идёт в JSON, Markdown и окно в GUI — чтобы не появилось три версии
правды.

**Чего инструмент не делает**

Честный список ограничений:

- TLS 1.3-сертификаты зашифрованы — правила на сертификатах работают только
  для TLS 1.2;
- HTTP/2 поверх TLS виден только при `SSLKEYLOGFILE`;
- brotli и zstd не распаковываются;
- SMB1 и SMB3-шифрование не разбираются;
- бюджет склейки TCP — 200 МБ, дальше потоки помечаются truncated;
- exe для Windows не подписан, SmartScreen ругается (SHA256SUMS рядом);
- плагины детекторов — произвольный Python, по умолчанию выключены.

**Цифры**

- 30 детекторов, 13 правил, 12 экстракторов, 9 вкладок GUI;
- 1656 тестов, покрытие ядра 87,1%;
- проверено на FIN-2015 (58 pcap, 4,7 ГБ), CyberCampTask (334 МБ) и
  malware-traffic-analysis 2025-06-13;
- 37 дней, 234 коммита, ~49 тысяч строк ядра и GUI.

**Зачем мне это**

Я руководитель отдела информационной безопасности, и такие задачи приходят
ко мне не «на посмотреть», а «разберись к утру». Инструмент сначала писался
под собственные разборы, поэтому в нём есть то, чего не хватало мне: одна
команда, понятный отчёт и объяснение, которое можно отдать коллеге без
пересказа.

**Ссылки**

- Код и релизы: https://github.com/v314xm/paradox
- Сайт: https://paradoxtool.ru
- Лицензия: MIT

Если попробуете на своём захвате и что-то не сойдётся — пишите в issues.
Особенно интересны случаи, где инструмент молчит, а атака есть: это самый
полезный вид фидбека.

---

## 4. Reddit: короткий пост (EN)

Сабы по приоритету: **r/DFIR** (основной), **r/blueteamsec**,
**r/cybersecurity**. В r/netsec self-promotion ограничен — только в
ежемесячном tool-треде, иначе пост снесут.

**Title:**

```text
Paradox — offline PCAP triage with a cross-source contradiction layer (30 detectors, 13 rules, open source)
```

**Body:**

```text
I built Paradox, a free MIT-licensed triage tool for PCAPs. It runs offline,
takes one command, and instead of only listing findings it reports where
different layers of the capture disagree.

What "contradiction" means here:
- DNS says one IP, SNI says another
- browser User-Agent with a tool's JA3
- two MACs on one IP (ARP spoofing)
- a workstation (by OUI) suddenly serving HTTP
- a host that is a brute-force victim and also attacks someone else -> pivot

Why I care: in real incidents the data usually contradicts itself, and the
contradiction is the fastest path to the pivot host. A list of alerts does not
tell you who is the victim and who is the attacker.

What's inside: 12 extractors, 30 detectors, 13 contradiction rules, timeline,
attack graph, JSON/Markdown/HTML/STIX reports, and a PySide6 GUI with 9 tabs.
Every finding and contradiction has a plain-language explanation (what happened
/ why it matters / what to check next / where the detector can be wrong).

Numbers: 1656 tests, 87% core coverage, 334 MB / 627k packets in 14.4 s on one
core. Validated on FIRST-2015 (58 pcaps, 4.7 GB), CyberCampTask and a
malware-traffic-analysis capture.

Limitations, so nobody is surprised: TLS 1.3 certificates are encrypted
(certificate rules are TLS 1.2 only), HTTP/2 over TLS needs SSLKEYLOGFILE,
brotli/zstd are not decompressed, SMB3 encryption is not parsed, the Windows
installer is unsigned.

Links:
- GitHub: https://github.com/v314xm/paradox
- Site: https://paradoxtool.ru
- English README: https://github.com/v314xm/paradox/blob/main/README.en.md

Feedback is welcome, especially false negatives: a capture where the tool stays
silent but something malicious is there.
```

**Комментарии.** Отвечать на каждый в первые 2–3 часа — алгоритм сабов
поднимает живые обсуждения. Не спорить с «ещё один Wireshark»: отвечать
«верно, это слой поверх: triage, а не замена». Не просить звёзды в посте.

---

## 5. Короткие версии

**SecurityLab / Telegram (RU):**

```text
Paradox — оффлайн-триаж pcap с слоем противоречий: 30 детекторов, 13 правил
(DNS vs SNI, JA3 vs UA, MAC vs IP, роль vs поведение), JSON/Markdown/HTML/STIX
и GUI. 627k пакетов за 14,4 с, 1656 тестов, MIT.
Windows exe (без подписи) и исходники: https://github.com/v314xm/paradox
```

**X / Twitter (EN, до 280 символов):**

```text
Paradox: offline PCAP triage that reports contradictions, not just findings —
DNS vs SNI, JA3 vs UA, MAC vs IP, role vs behaviour. 30 detectors, 13 rules,
1656 tests, MIT. Windows exe + source.
https://github.com/v314xm/paradox
```

**LinkedIn (EN/RU):** тот же текст + один скриншот, без хештегов-простыней,
3–5 тегов (`#DFIR #ThreatHunting #OpenSource`).

---

## 6. Порядок публикации и замеры

День 0:

1. GitHub description, topics, social preview, README.en.md.
2. GIF в оба README.
3. Release notes 1.9.0 в 5 строк.

День 1: Habr (утро, будни), затем через 3–4 часа Reddit r/DFIR. Не в один
час — нужны силы отвечать в комментариях.

День 2: r/blueteamsec, SecurityLab, Telegram-каналы по DFIR, X/LinkedIn.

День 7: пост-продолжение «что я поменял по фидбеку» — второй заход в ту же
аудиторию.

Что мерить раз в неделю:

| Метрика | Где | Ориентир после одного поста |
|---|---|---|
| Скачивания setup.exe | GitHub API releases | 20–100 |
| Звёзды | API repo | 10–50 |
| `git clone` | API `/traffic/clones` (нужен токен) | 30–150 |
| Issues/обсуждения | GitHub | 1–5 |

Если после поста цифры нулевые — проблема в упаковке (заголовок, гифка,
первый экран), а не в инструменте. Проверять по одному элементу, не менять
всё сразу.

---

## 7. Чего не делать

- Не сравнивать в лоб с Wireshark/Zeek/Suricata: другая задача, аудитория
  это знает; сравнение читается как маркетинг.
- Не писать «революционный», «убийца Wireshark», «искусственный интеллект»
  там, где обычная статистика.
- Не постить один и тот же текст в 10 сабов за час — это спам, аккаунт
  забанят.
- Не просить звёзд и не устраивать голосование.
- Не показывать реальные IP/учётки из рабочих захватов — только публичные
  датасеты.
