"""Вкладка «Развитие» — статический роадмап проекта.

Никаких зависимостей от ядра, никаких сигналов и состояния.
Смысл вкладки: единое место, где видно, что сделано, что в работе,
что отложено, и какие у GUI известные ограничения.

Почему QTextBrowser, а не стопка QLabel в QScrollArea:
    - бесплатно даёт скролл, выделение текста, Ctrl+C
    - HTML правится в одном месте, без верстки десятка виджетов
    - ссылки (если появятся) откроются без доп. кода

Ключевое решение: цвета в HTML захардкожены, не тянутся из PALETTE.
Причина — QTextBrowser рендерит свой QTextDocument, и QSS на его
содержимое не распространяется. Значения вручную согласованы
с PALETTE/SEVERITY из theme.py.
"""
from PySide6.QtWidgets import QTextBrowser, QVBoxLayout, QWidget


# Содержимое — единственная точка правки. Обновляется руками.
# Отступ HTML не в столбик 0 ради читаемости diff'ов.
_ROADMAP_HTML = """
<style>
    h2    { color: #e0e0e0; font-size: 17px; margin-bottom: 4px; }
    h3    { color: #5b8cff; font-size: 14px; margin-top: 16px; margin-bottom: 4px; }
    p, li { color: #e0e0e0; font-size: 13px; }
    ul    { margin-top: 4px; margin-bottom: 4px; }
    li    { margin-bottom: 2px; }
    .done { color: #50fa7b; }
    .wip  { color: #f1fa8c; }
    .plan { color: #a0a0b0; }
    .note { color: #a0a0b0; font-size: 12px; }
    code  { color: #8be9fd; }
</style>

<h2>Развитие pcap-triage GUI</h2>
<p class="note">
    Ядро <code>pcap_triage/</code> не трогаем. GUI — отдельный пакет,
    работает через контракт <code>run_pipeline(pcap_path, config) -&gt; dict</code>.
</p>

<h3>Готово в v0.7.0</h3>
<ul>
    <li class="done">Вкладка «Прогон»: drop zone, summary grid, противоречия, findings, toast, progress</li>
    <li class="done">Вкладка «Настройки» — 11 секций: Пороги, Детекторы, Противоречия, Allowlist, DGA, Brute force, Сеть, Отчёты, Threat Intel, Производительность. «Общие» — заглушка с описанием</li>
    <li class="done">Вкладка «Обогащение»: Threat Intel по выбранным IOC (Shodan InternetDB, AbuseIPDB)</li>
    <li class="done">Вкладка «История»: in-memory список прогонов с обогащением, маркер ✓ enriched</li>
    <li class="done">Вкладка «Развитие»: этот экран</li>
    <li class="done">Экспорт: JSON, Markdown, conn.log</li>
    <li class="done">Сборка .exe через PyInstaller (onedir, без консоли, collect_submodules ядра)</li>
    <li class="done">Меню, горячие клавиши (Ctrl+O с кириллицей), статус-бар, тёмная тема</li>
</ul>

<h3>Ближайшие шаги</h3>
<ul>
    <li class="plan">E — остановка анализа: QThread.terminate() валит процесс. Нужен detach-подход: отключить сигналы, держать воркер в списке, пока не досчитает в фоне</li>
    <li class="plan">Иконка .ico для .exe и окна приложения</li>
    <li class="plan">Сравнение двух прогонов (diff findings между записями истории)</li>
</ul>

<h3>Идеи на потом</h3>
<ul>
    <li class="plan">Экспорт отчёта в PDF</li>
    <li class="plan">Светлая тема / переключатель тем</li>
    <li class="plan">Плагины для кастомных детекторов</li>
    <li class="plan">Сохранение истории на диск (SQLite) вместо in-memory</li>
    <li class="plan">Сохранение API-ключей в .env (сейчас — только os.environ, до перезапуска)</li>
</ul>

<h3>Известные ограничения</h3>
<ul>
    <li class="plan">Progress bar — indeterminate: ядро пишет прогресс в stdout, callback не отдаёт. Правка ядра запрещена</li>
    <li class="plan">Config — frozen dataclass: переопределения из GUI идут через <code>object.__setattr__</code>. Мердж через <code>dict.update()</code>, чтобы применения разных секций не затирали друг друга</li>
    <li class="plan">Severity findings в ядре нет: в таблице столбец не показываем</li>
    <li class="plan">Ядро — только импорт, monkey-patch DETECTORS / RULES в воркере с откатом в <code>finally</code></li>
    <li class="plan">VirusTotal в ядре не подключён к pipeline обогащения — поле в настройках пока без потребителя</li>
</ul>
"""


class RoadmapView(QWidget):
    """Статический роадмап. Без сигналов, без состояния — только HTML."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(0)

        browser = QTextBrowser()
        browser.setObjectName("roadmapBrowser")
        browser.setOpenExternalLinks(True)
        browser.setHtml(_ROADMAP_HTML)
        layout.addWidget(browser)