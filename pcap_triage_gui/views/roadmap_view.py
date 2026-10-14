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
    <li class="done">Вкладка «Настройки»: Пороги, Детекторы, Противоречия — end-to-end</li>
    <li class="done">Экспорт: JSON, Markdown, conn.log</li>
    <li class="done">Меню, горячие клавиши, статус-бар, тёмная тема</li>
</ul>

<h3>Ближайшие шаги</h3>
<ul>
    <li class="wip">B — вкладка «Развитие» (этот экран)</li>
    <li class="plan">D — PyInstaller → .exe (после стабилизации GUI)</li>
    <li class="plan">A — секции Allowlist / Brute force / Сеть / Производительность в «Настройках»</li>
    <li class="plan">C — вкладка «История» (in-memory список прогонов, без БД)</li>
    <li class="plan">E — остановка анализа (требует worker.terminate — рискованно)</li>
    <li class="plan">F — обогащение (AbuseIPDB, нужен API-ключ и сеть)</li>
</ul>

<h3>Идеи на потом</h3>
<ul>
    <li class="plan">Сравнение двух прогонов (diff findings)</li>
    <li class="plan">Экспорт отчёта в PDF</li>
    <li class="plan">Светлая тема / переключатель тем</li>
    <li class="plan">Плагины для кастомных детекторов</li>
</ul>

<h3>Известные ограничения</h3>
<ul>
    <li class="plan">Progress bar — indeterminate: ядро пишет прогресс в stdout, callback не отдаёт</li>
    <li class="plan">Config — frozen dataclass: переопределения из GUI идут через <code>object.__setattr__</code></li>
    <li class="plan">Severity findings в ядре нет: в таблице столбец не показываем</li>
    <li class="plan">Ядро — только импорт, monkey-patch DETECTORS / RULES в воркере с откатом в <code>finally</code></li>
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