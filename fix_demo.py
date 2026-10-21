import re
from pathlib import Path

file_path = Path("docs/index.html")

if not file_path.exists():
    print("Ошибка: файл docs/index.html не найден!")
    exit(1)

content = file_path.read_text(encoding="utf-8")

# Новый улучшенный HTML для Live Demo
new_demo_html = """    <!-- LIVE DEMO / ИНТЕРАКТИВНЫЙ ИНТЕРФЕЙС -->
    <section id="live-demo" class="max-w-6xl mx-auto px-6 mb-24 fade-in">
        <div class="text-center mb-12">
            <h2 class="text-3xl md:text-4xl font-bold mb-4">Живой интерфейс Paradox</h2>
            <p class="text-slate-400 max-w-2xl mx-auto">Нажмите на вкладки ниже, чтобы посмотреть, как выглядит работа с инструментом.</p>
        </div>

        <!-- Окно приложения -->
        <div class="bg-[#1e1e2e] rounded-lg border border-[#313342] shadow-2xl overflow-hidden flex flex-col font-sans" style="min-height: 500px;">

            <!-- Заголовок окна -->
            <div class="bg-[#282a36] px-4 py-2 flex items-center justify-between border-b border-[#3a3d4d]">
                <div class="flex items-center gap-4">
                    <div class="flex gap-2">
                        <div class="w-3 h-3 rounded-full bg-red-500"></div>
                        <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
                        <div class="w-3 h-3 rounded-full bg-green-500"></div>
                    </div>
                    <span class="text-sm text-slate-300 font-mono ml-2">Paradox v1.0.0 — CyberCampTask.pcap</span>
                </div>
                <div class="text-xs text-slate-500 font-mono">— □ ×</div>
            </div>

            <!-- Вкладки -->
            <div class="flex bg-[#282a36] border-b border-[#3a3d4d] px-2 text-sm">
                <button class="demo-tab active px-6 py-2.5 text-slate-300 border-b-2 border-[#5b8cff] bg-[#1e1e2e] font-medium" data-target="demo-run">Прогон</button>
                <button class="demo-tab px-6 py-2.5 text-slate-400 border-b-2 border-transparent hover:text-slate-200 transition-colors" data-target="demo-timeline">Таймлайн</button>
                <button class="demo-tab px-6 py-2.5 text-slate-400 border-b-2 border-transparent hover:text-slate-200 transition-colors" data-target="demo-graph">Граф атаки</button>
            </div>

            <!-- Контент вкладок -->
            <div class="flex-1 relative bg-[#1e1e2e] p-6">

                <!-- ВКЛАДКА 1: ПРОГОН -->
                <div id="demo-run" class="demo-pane active animate-fadeIn">
                    <!-- Карточки -->
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        <div class="bg-[#282a36] border border-[#3a3d4d] rounded-lg p-4 text-center">
                            <div class="text-2xl font-bold text-[#5b8cff] font-mono">627 694</div>
                            <div class="text-xs text-slate-400 mt-1">Пакеты</div>
                        </div>
                        <div class="bg-[#282a36] border border-[#3a3d4d] rounded-lg p-4 text-center">
                            <div class="text-2xl font-bold text-[#5b8cff] font-mono">2 332</div>
                            <div class="text-xs text-slate-400 mt-1">Flows</div>
                        </div>
                        <div class="bg-[#282a36] border border-[#3a3d4d] rounded-lg p-4 text-center">
                            <div class="text-2xl font-bold text-[#5b8cff] font-mono">7</div>
                            <div class="text-xs text-slate-400 mt-1">Findings</div>
                        </div>
                        <div class="bg-[#282a36] border border-rose-500/30 rounded-lg p-4 text-center relative overflow-hidden">
                            <div class="absolute inset-0 bg-rose-500/5"></div>
                            <div class="text-2xl font-bold text-rose-400 font-mono relative">2</div>
                            <div class="text-xs text-rose-400 mt-1 relative">Противоречия</div>
                        </div>
                    </div>

                    <!-- Таблица -->
                    <div class="bg-[#282a36] border border-[#3a3d4d] rounded-lg overflow-hidden">
                        <div class="px-4 py-2 border-b border-[#3a3d4d] text-xs font-semibold text-slate-400 uppercase tracking-wider">Найдено в трафике</div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm text-left">
                                <thead class="text-xs text-slate-400 bg-[#1e1e2e] border-b border-[#3a3d4d]">
                                    <tr>
                                        <th class="px-4 py-3 font-medium">Тип</th>
                                        <th class="px-4 py-3 font-medium">Значение</th>
                                        <th class="px-4 py-3 font-medium">MITRE</th>
                                        <th class="px-4 py-3 font-medium">Severity</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-[#3a3d4d]">
                                    <tr class="hover:bg-[#313342] cursor-pointer transition-colors">
                                        <td class="px-4 py-2.5 text-slate-200">FTP brute force</td>
                                        <td class="px-4 py-2.5 font-mono text-slate-400 text-xs">10.0.1.50 → 192.168.1.12:21</td>
                                        <td class="px-4 py-2.5 text-[#5b8cff] font-mono">T1110.001</td>
                                        <td class="px-4 py-2.5"><span class="bg-rose-500/20 text-rose-400 px-2 py-0.5 rounded text-xs font-bold border border-rose-500/30">critical</span></td>
                                    </tr>
                                    <tr class="hover:bg-[#313342] cursor-pointer transition-colors">
                                        <td class="px-4 py-2.5 text-slate-200">Command injection</td>
                                        <td class="px-4 py-2.5 font-mono text-slate-400 text-xs">10.0.1.50 → 192.168.1.12:80</td>
                                        <td class="px-4 py-2.5 text-[#5b8cff] font-mono">T1190</td>
                                        <td class="px-4 py-2.5"><span class="bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded text-xs font-bold border border-amber-500/30">high</span></td>
                                    </tr>
                                    <tr class="hover:bg-[#313342] cursor-pointer transition-colors bg-[#313342]/50">
                                        <td class="px-4 py-2.5 text-slate-200">Lateral movement</td>
                                        <td class="px-4 py-2.5 font-mono text-slate-400 text-xs">192.168.1.12 → 192.168.1.1:5985</td>
                                        <td class="px-4 py-2.5 text-[#5b8cff] font-mono">T1021.001</td>
                                        <td class="px-4 py-2.5"><span class="bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded text-xs font-bold border border-amber-500/30">high</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ВКЛАДКА 2: ТАЙМЛАЙН -->
                <div id="demo-timeline" class="demo-pane animate-fadeIn">
                    <div class="space-y-3">
                        <div class="flex gap-4">
                            <div class="w-20 text-xs text-slate-500 font-mono pt-2 text-right">00:00:18</div>
                            <div class="flex-1 bg-[#282a36] border-l-2 border-amber-500 rounded-r-lg p-3">
                                <div class="flex justify-between items-center mb-1">
                                    <span class="text-sm font-bold text-amber-400">INITIAL_ACCESS</span>
                                    <span class="text-xs text-slate-500 font-mono bg-[#1e1e2e] px-2 py-0.5 rounded">T1110.001</span>
                                </div>
                                <p class="text-sm text-slate-300 font-mono">ftp_brute_force (10.0.1.50 → 192.168.1.12)</p>
                            </div>
                        </div>
                        <div class="flex gap-4">
                            <div class="w-20 text-xs text-slate-500 font-mono pt-2 text-right">00:05:07</div>
                            <div class="flex-1 bg-[#282a36] border-l-2 border-rose-500 rounded-r-lg p-3">
                                <div class="flex justify-between items-center mb-1">
                                    <span class="text-sm font-bold text-rose-400">EXECUTION</span>
                                    <span class="text-xs text-slate-500 font-mono bg-[#1e1e2e] px-2 py-0.5 rounded">T1190</span>
                                </div>
                                <p class="text-sm text-slate-300 font-mono">command_injection (10.0.1.50 → 192.168.1.12)</p>
                            </div>
                        </div>
                        <div class="flex gap-4">
                            <div class="w-20 text-xs text-slate-500 font-mono pt-2 text-right">00:10:56</div>
                            <div class="flex-1 bg-[#282a36] border-l-2 border-sky-500 rounded-r-lg p-3">
                                <div class="flex justify-between items-center mb-1">
                                    <span class="text-sm font-bold text-sky-400">LATERAL_MOVEMENT</span>
                                    <span class="text-xs text-slate-500 font-mono bg-[#1e1e2e] px-2 py-0.5 rounded">T1021.001</span>
                                </div>
                                <p class="text-sm text-slate-300 font-mono">victim_makes_attack: 192.168.1.12 → 192.168.1.1</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ВКЛАДКА 3: ГРАФ -->
                <div id="demo-graph" class="demo-pane animate-fadeIn flex justify-center items-center h-full min-h-[400px]">
                    <svg viewBox="0 0 800 400" class="w-full h-full max-h-[500px]">
                        <!-- Маркеры (стрелки) -->
                        <defs>
                            <marker id="arrow-gray" viewBox="0 0 10 10" refX="35" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                                <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
                            </marker>
                            <marker id="arrow-blue" viewBox="0 0 10 10" refX="35" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                                <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
                            </marker>
                            <marker id="arrow-red" viewBox="0 0 10 10" refX="35" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                                <path d="M 0 0 L 10 5 L 0 10 z" fill="#f87171" />
                            </marker>
                        </defs>

                        <!-- Линии -->
                        <line x1="160" y1="200" x2="340" y2="200" stroke="#64748b" stroke-width="2" marker-end="url(#arrow-gray)"/>
                        <line x1="420" y1="200" x2="570" y2="120" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow-blue)"/>
                        <line x1="420" y1="200" x2="570" y2="280" stroke="#f87171" stroke-width="2" marker-end="url(#arrow-red)"/>

                        <!-- Узлы -->
                        <!-- 10.0.1.50 (Вход) -->
                        <circle cx="130" cy="200" r="30" fill="#282a36" stroke="#f87171" stroke-width="2"/>
                        <text x="130" y="200" text-anchor="middle" dominant-baseline="central" fill="#f87171" font-size="10" font-family="monospace">10.0.1.50</text>
                        <text x="130" y="240" text-anchor="middle" fill="#64748b" font-size="10" font-family="sans-serif">Вход / Жертва</text>

                        <!-- 192.168.1.12 (Pivot) -->
                        <circle cx="380" cy="200" r="30" fill="#282a36" stroke="#fbbf24" stroke-width="2"/>
                        <text x="380" y="200" text-anchor="middle" dominant-baseline="central" fill="#fbbf24" font-size="10" font-family="monospace">192.168.1.12</text>
                        <text x="380" y="240" text-anchor="middle" fill="#fbbf24" font-size="11" font-weight="bold">Pivot</text>

                        <!-- 192.168.1.1 (Impact) -->
                        <circle cx="600" cy="120" r="30" fill="#282a36" stroke="#4ade80" stroke-width="2"/>
                        <text x="600" y="120" text-anchor="middle" dominant-baseline="central" fill="#4ade80" font-size="10" font-family="monospace">192.168.1.1</text>
                        <text x="600" y="160" text-anchor="middle" fill="#64748b" font-size="10" font-family="sans-serif">Жертва</text>

                        <!-- 80.64.102.71 (C2) -->
                        <circle cx="600" cy="280" r="30" fill="#282a36" stroke="#f87171" stroke-width="2"/>
                        <text x="600" y="280" text-anchor="middle" dominant-baseline="central" fill="#f87171" font-size="10" font-family="monospace">80.64.102.71</text>
                        <text x="600" y="320" text-anchor="middle" fill="#f87171" font-size="10" font-family="sans-serif">C2 / Цель</text>
                    </svg>
                </div>
            </div>
        </div>
    </section>
"""

# Регулярное выражение для поиска старого блока Live Demo
# Ищем от комментария "LIVE DEMO" до комментария "INTERFACE SHOWCASE"
pattern = re.compile(r'(<!-- LIVE DEMO.*?-->)(.*?)(?=<!-- INTERFACE SHOWCASE -->)', re.DOTALL)

# Заменяем старый блок на новый
if pattern.search(content):
    content = pattern.sub(new_demo_html + "\n\n    ", content)
    print("Старый блок Live Demo успешно заменен на улучшенный!")
else:
    # Если регулярка не сработала (например, нет комментариев), попробуем найти по id
    print("Регулярное выражение не сработало, пробуем поиск по ID...")
    pattern_id = re.compile(r'(<section id="live-demo".*?</section>)', re.DOTALL)
    if pattern_id.search(content):
        content = pattern_id.sub(new_demo_html, content)
        print("Блок Live Demo заменен по ID!")
    else:
        print("Не удалось найти блок Live Demo в файле. Возможно, скрипт уже был запущен.")
        exit(1)

# Сохраняем файл
file_path.write_text(content, encoding="utf-8")
print("Готово! Файл успешно обновлен.")
