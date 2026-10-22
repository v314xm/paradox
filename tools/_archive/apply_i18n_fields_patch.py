#!/usr/bin/env python3
"""i18n-патч: подписи полей и подсказки в SettingsView + field_help.py."""
from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SV = ROOT / "paradox_gui" / "views" / "settings_view.py"
FH = ROOT / "paradox_gui" / "field_help.py"
I18N_RU = ROOT / "paradox_gui" / "i18n" / "_ru.py"
I18N_EN = ROOT / "paradox_gui" / "i18n" / "_en.py"


# ---------------------------------------------------------------------------
# 1. Подписи полей (рядом со спиннерами)
# ---------------------------------------------------------------------------
FIELD_LABELS = {
    "dga_min_label_length":             ("DGA: минимальная длина label", "DGA: min label length"),
    "dga_entropy_threshold":            ("DGA: порог энтропии", "DGA: entropy threshold"),
    "nxdomain_burst_threshold":         ("NXDOMAIN burst: порог", "NXDOMAIN burst: threshold"),
    "nxdomain_burst_window_sec":        ("NXDOMAIN burst: окно (сек)", "NXDOMAIN burst: window (sec)"),
    "nxdomain_burst_min_ratio":         ("NXDOMAIN burst: мин. доля NXDOMAIN", "NXDOMAIN burst: min NXDOMAIN ratio"),
    "dns_tunneling_min_qname_length":   ("DNS tunneling: мин. длина qname", "DNS tunneling: min qname length"),
    "dns_tunneling_min_queries":        ("DNS tunneling: мин. запросов", "DNS tunneling: min queries"),
    "brute_force_min_flows":            ("Brute force: мин. flows", "Brute force: min flows"),
    "brute_force_max_avg_packets":      ("Brute force: макс. avg packets", "Brute force: max avg packets"),
    "ftp_brute_force_min_flows":        ("FTP brute force: мин. flows", "FTP brute force: min flows"),
    "beaconing_min_connections":        ("Beaconing: мин. соединений", "Beaconing: min connections"),
    "beaconing_min_duration_sec":       ("Beaconing: мин. длительность (сек)", "Beaconing: min duration (sec)"),
    "beaconing_max_jitter_ratio":       ("Beaconing: макс. jitter", "Beaconing: max jitter"),
    "large_transfer_min_bytes":         ("Large transfer: мин. байт", "Large transfer: min bytes"),
    "port_scan_min_distinct_dsts":      ("Port scan: мин. dsts", "Port scan: min dsts"),
    "port_scan_max_flows_per_dst":      ("Port scan: макс. flows/dst", "Port scan: max flows/dst"),
    "reverse_asymmetry_min_ratio":      ("Reverse asymmetry: мин. ratio", "Reverse asymmetry: min ratio"),
    "reverse_asymmetry_min_total_bytes": ("Reverse asymmetry: мин. байт", "Reverse asymmetry: min bytes"),
    "brute_force_min_unique_src_ports": ("HTTP: мин. уникальных src-портов", "HTTP: min unique src ports"),
    "brute_force_uri_ratio_threshold":  ("HTTP: доля запросов к login-endpoint", "HTTP: login-endpoint request ratio"),
    "brute_force_min_rate_flows_per_sec": ("HTTP: мин. скорость (flows/сек)", "HTTP: min rate (flows/sec)"),
    "ftp_brute_force_min_unique_src_ports": ("FTP: мин. уникальных src-портов", "FTP: min unique src ports"),
}


# ---------------------------------------------------------------------------
# 2. Подсказки под подписями (из field_help.py)
# ---------------------------------------------------------------------------
FIELD_HINTS = {
    "dga_min_label_length": (
        "Минимальная длина label (часть домена до первой точки). Короче — DGA не считаем, слишком много легитимных доменов.",
        "Minimum label length (part before the first dot). Shorter — not DGA, too many legitimate domains.",
    ),
    "dga_entropy_threshold": (
        "Порог энтропии Шеннона для label. Выше — похоже на случайный набор символов (xg7f2k9vbn).",
        "Shannon entropy threshold for label. Higher — looks random (xg7f2k9vbn).",
    ),
    "nxdomain_burst_threshold": (
        "Сколько NXDOMAIN-ответов в окне считать burst'ом.",
        "Number of NXDOMAIN responses in window to count as a burst.",
    ),
    "nxdomain_burst_window_sec": (
        "Размер окна в секундах. Проверяется максимум во всех окнах длиной W от одного src.",
        "Window size in seconds. Checks the maximum across all W-second windows from one src.",
    ),
    "nxdomain_burst_min_ratio": (
        "Минимальная доля NXDOMAIN среди всех DNS-запросов от src. Ниже — шум (браузер с редкими опечатками).",
        "Minimum NXDOMAIN share among all DNS queries from src. Below — noise (browser with rare typos).",
    ),
    "dns_tunneling_min_qname_length": (
        "Минимальная длина qname для DNS-туннеля. Короче — это DGA-зона, не туннель.",
        "Minimum qname length for DNS tunnel. Shorter — DGA zone, not tunnel.",
    ),
    "dns_tunneling_min_queries": (
        "Минимум DNS-запросов к одному базовому домену, чтобы считать это туннелем.",
        "Min DNS queries to one base domain to count as a tunnel.",
    ),
    "brute_force_min_flows": (
        "Минимум flows для HTTP brute force.",
        "Min flows for HTTP brute force.",
    ),
    "brute_force_max_avg_packets": (
        "Максимум среднего числа пакетов на flow. Больше — уже не брутфорс (браузер грузит сайт).",
        "Max average packets per flow. Higher — not brute force (browser loading a site).",
    ),
    "ftp_brute_force_min_flows": (
        "Минимум flows для FTP brute force. FTP-сессия длиннее, поэтому порог выше.",
        "Min flows for FTP brute force. FTP session is longer, so threshold is higher.",
    ),
    "beaconing_min_connections": (
        "Минимум соединений к одной паре (src, dst, port) для beaconing.",
        "Min connections to one (src, dst, port) pair for beaconing.",
    ),
    "beaconing_min_duration_sec": (
        "Минимальная длительность наблюдения. Короткий всплеск — не C2-heartbeat.",
        "Minimum observation duration. Short burst — not a C2 heartbeat.",
    ),
    "beaconing_max_jitter_ratio": (
        "Максимальный jitter = stddev / mean интервалов. Меньше — ровнее тайминг, сильнее сигнал C2.",
        "Max jitter = stddev / mean of intervals. Lower — smoother timing, stronger C2 signal.",
    ),
    "large_transfer_min_bytes": (
        "Порог «большой трансфер» в байтах.",
        "'Large transfer' threshold in bytes.",
    ),
    "port_scan_min_distinct_dsts": (
        "Минимум уникальных dst-адресов от одного src для port scan.",
        "Min unique dst addresses from one src for port scan.",
    ),
    "port_scan_max_flows_per_dst": (
        "Максимум flows на один dst. Больше — это уже работа с сервисом, не скан.",
        "Max flows to one dst. Higher — this is service interaction, not a scan.",
    ),
    "reverse_asymmetry_min_ratio": (
        "Во сколько раз большая сторона сессии должна превышать меньшую. 10:1 — аномалия, 25:1 — почти односторонний канал.",
        "How many times larger the bigger side must be. 10:1 — anomaly, 25:1 — nearly one-way channel.",
    ),
    "reverse_asymmetry_min_total_bytes": (
        "Минимальный суммарный объём сессии. Ниже — не смотрим.",
        "Minimum total session volume. Below — not analyzed.",
    ),
    "brute_force_min_unique_src_ports": (
        "Минимум уникальных src-портов. Сильный сигнал подбора пароля.",
        "Min unique src ports. Strong password-guessing signal.",
    ),
    "brute_force_uri_ratio_threshold": (
        "Доля запросов к login-endpoint от всех. Ниже — не брутфорс.",
        "Share of requests to login-endpoint. Below — not brute force.",
    ),
    "brute_force_min_rate_flows_per_sec": (
        "Минимальная скорость flows/сек. Отсекает медленные легитимные повторы.",
        "Minimum rate flows/sec. Cuts slow legitimate retries.",
    ),
    "ftp_brute_force_min_unique_src_ports": (
        "Минимум уникальных src-портов для FTP brute force.",
        "Min unique src ports for FTP brute force.",
    ),
    "brute_force_skip_tls_ports": (
        "Порты с TLS, где brute force не ищем: там User-Agent не читается, признак не работает.",
        "TLS ports where brute force isn't detected: User-Agent unreadable, signal doesn't work.",
    ),
    "login_endpoint_hints": (
        "Подстроки URI, по которым определяем login-endpoint: /login, /admin, /wp-login, …",
        "URI substrings identifying login-endpoint: /login, /admin, /wp-login, …",
    ),
    "suspicious_ports": (
        "Порты, которые считаются подозрительными: 4444, 31337, 1337…",
        "Ports considered suspicious: 4444, 31337, 1337…",
    ),
    "port_scan_excluded_ports": (
        "Порты, которые исключаем из port scan — типичный web-трафик.",
        "Ports excluded from port scan — typical web traffic.",
    ),
    "dc_service_ports": (
        "Порты domain controller: Kerberos, LDAP, SMB. Их наличие + много flows отличает DC от обычного сервера.",
        "Domain controller ports: Kerberos, LDAP, SMB. Presence + many flows distinguishes a DC from a regular server.",
    ),
    "lateral_movement_ports": (
        "Порты lateral movement: SMB, RDP, WinRM, MSRPC.",
        "Lateral movement ports: SMB, RDP, WinRM, MSRPC.",
    ),
    "beaconing_mail_polling_ports": (
        "POP3/IMAP-порты. Почтовый клиент дёргает ящик по таймеру — это не C2-beaconing.",
        "POP3/IMAP ports. Mail client polls on a timer — not C2 beaconing.",
    ),
    "private_networks": (
        "Префиксы приватных сетей. Используется для классификации dst как «внутренний» или «внешний».",
        "Private network prefixes. Used to classify dst as internal or external.",
    ),
    "tcp_reassembly_enabled": (
        "Склеивать TCP-сегменты в потоки. Даёт полные ClientHello и HTTP body, но расходует память.",
        "Reassemble TCP segments into streams. Gives full ClientHello and HTTP body, uses memory.",
    ),
    "tcp_reassembly_max_bytes_per_flow": (
        "Лимит памяти на один flow при reassembly.",
        "Memory limit per flow during reassembly.",
    ),
    "tcp_reassembly_max_total_bytes": (
        "Общий лимит памяти на reassembly. Защита от гигабайтных pcap.",
        "Total memory limit for reassembly. Protection from GB-sized pcaps.",
    ),
    "file_carve_enabled": (
        "Извлекать метаданные payload'ов (sha256, тип, размер). Без записи содержимого на диск.",
        "Extract payload metadata (sha256, type, size). Without writing content to disk.",
    ),
    "file_carve_write_body": (
        "Писать тела файлов на диск как <sha256>.bin. Осторожно: много места.",
        "Write file bodies to disk as <sha256>.bin. Caution: takes a lot of space.",
    ),
    "file_carve_min_size": (
        "Минимальный размер payload для file carve.",
        "Minimum payload size for file carve.",
    ),
    "file_carve_max_size": (
        "Максимальный размер payload для file carve.",
        "Maximum payload size for file carve.",
    ),
    "entities_top_n": (
        "Сколько top-сущностей (по активности) показывать в отчёте.",
        "How many top entities (by activity) to show in the report.",
    ),
    "flow_report_top_n": (
        "Сколько top-flow'ов по байтам включать в flow report.",
        "How many top flows by bytes to include in flow report.",
    ),
    "beaconing_allowlist_suffixes": (
        "Суффиксы SNI/Host, для которых beaconing не считаем: analytics, CDN, cloud.",
        "SNI/Host suffixes where beaconing is skipped: analytics, CDN, cloud.",
    ),
    "beaconing_allowlist_ips": (
        "Точные IP без SNI, для которых beaconing не считаем.",
        "Exact IPs (no SNI) where beaconing is skipped.",
    ),
    "dns_tunneling_allowlist": (
        "DoH-домены: dns.google, cloudflare-dns.com. Не считать туннелем.",
        "DoH domains: dns.google, cloudflare-dns.com. Not counted as tunnel.",
    ),
    "sni_mismatch_allowlist": (
        "Известные проверочные домены (OCSP, CRL, DoH), у которых SNI ≠ Host штатно.",
        "Known validation domains (OCSP, CRL, DoH) where SNI ≠ Host by design.",
    ),
    "large_transfer_excluded_hosts": (
        "Хосты, для которых большие трансферы норма: обновления Windows, Apple.",
        "Hosts where large transfers are normal: Windows and Apple updates.",
    ),
    "large_transfer_excluded_user_agents": (
        "User-Agent'ы, для которых большие трансферы норма: BITS, CryptoAPI, Delivery Optimization.",
        "User-Agents where large transfers are normal: BITS, CryptoAPI, Delivery Optimization.",
    ),
    "dga_allowlist": (
        "Итоговый allowlist DGA = extra + cloud tunnel + ip-check сервисы. Удаление элемента означает, что DGA начнёт ругаться на этот домен.",
        "Final DGA allowlist = extra + cloud tunnel + ip-check services. Removing an item means DGA will flag it.",
    ),
    "output_dir": (
        "Каталог для отчётов и артефактов. Создаётся при применении.",
        "Directory for reports and artifacts. Created on apply.",
    ),
    "enrichment_enabled_providers": (
        "Какие провайдеры использовать. Без ключа: shodan_internetdb, greynoise, alienvault_otx, urlscan. С ключом: abuseipdb, virustotal. С ABUSECH_AUTH_KEY: urlhaus, malwarebazaar, threatfox.",
        "Which providers to use. No key: shodan_internetdb, greynoise, alienvault_otx, urlscan. With key: abuseipdb, virustotal. With ABUSECH_AUTH_KEY: urlhaus, malwarebazaar, threatfox.",
    ),
    "enrichment_cache_ttl_days": (
        "TTL кэша обогащения в днях.",
        "Enrichment cache TTL in days.",
    ),
    "enrichment_cache_path": (
        "Путь к SQLite-файлу кэша обогащения.",
        "Path to SQLite enrichment cache file.",
    ),
    "enrichment_max_iocs": (
        "Сколько IOC обогащать за один прогон.",
        "How many IOCs to enrich per run.",
    ),
}


# ---------------------------------------------------------------------------
# 3. Placeholder
# ---------------------------------------------------------------------------
PLACEHOLDER_GENERAL = (
    (
        "<b>Что будет.</b> Общие настройки: <b>язык интерфейса</b> "
        "(русский / английский), путь к отчётам по умолчанию, "
        "поведение при старте (открывать последний pcap или пустую "
        "вкладку), тема оформления (сейчас тёмная — единственная)."
        "<br><br>"
        "<b>Почему пусто.</b> Сейчас эти значения либо захардкожены "
        "в GUI, либо не критичны. Появятся, когда появится вторая "
        "локализация или несколько профилей работы."
    ),
    (
        "<b>What's coming.</b> General settings: <b>UI language</b> "
        "(Russian / English), default reports path, startup behavior "
        "(open last pcap or empty tab), theme (currently dark-only)."
        "<br><br>"
        "<b>Why empty.</b> Currently these values are either hardcoded "
        "in GUI or not critical. Will appear with the second locale "
        "or multiple work profiles."
    ),
)

PLACEHOLDER_FALLBACK = ("Секция в разработке.", "Section in development.")
HELP_FALLBACK = (
    "Параметр «{key}» из Config ядра. См. paradox/config.py.",
    "Config field '{key}'. See paradox/config.py.",
)


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------
def _backup(p: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = p.with_name(f"{p.name}.{ts}.bak")
    shutil.copy2(p, bak)
    return bak


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _insert_keys(path: Path, block: str, marker: str, dry: bool, force: bool) -> bool:
    if not path.exists():
        print(f"  [warn] {path.name} не найден", file=sys.stderr)
        return False
    text = path.read_text(encoding="utf-8")
    if marker in text and not force:
        print(f"  {path.name}: ключи уже есть, скип")
        return False
    close_idx = text.rfind("\n}\n")
    if close_idx < 0:
        print(f"  [error] {path.name}: закрывающая }} не найдена",
              file=sys.stderr)
        return False
    new_text = text[:close_idx] + "\n" + block + text[close_idx:]
    try:
        ast.parse(new_text)
    except SyntaxError as e:
        print(f"  [error] {path.name}: синтаксис сломан: {e}",
              file=sys.stderr)
        return False
    if dry:
        print(f"  [dry] {path.name}: +{block.count(chr(10))} строк")
        return True
    _backup(path)
    path.write_text(new_text, encoding="utf-8")
    print(f"  {path.name}: записан")
    return True


def _patch_lang_files(dry: bool, force: bool) -> tuple[bool, bool]:
    ru_lines = ["    # --- SettingsView fields (этап 2) ---"]
    en_lines = ["    # --- SettingsView fields (stage 2) ---"]
    for key, (ru, en) in FIELD_LABELS.items():
        ru_lines.append(f'    "settings.field.{key}": "{_esc(ru)}",')
        en_lines.append(f'    "settings.field.{key}": "{_esc(en)}",')
    for key, (ru, en) in FIELD_HINTS.items():
        ru_lines.append(f'    "settings.help.{key}": "{_esc(ru)}",')
        en_lines.append(f'    "settings.help.{key}": "{_esc(en)}",')
    # Placeholders
    ru_lines.append(f'    "settings.placeholder.general": "{_esc(PLACEHOLDER_GENERAL[0])}",')
    en_lines.append(f'    "settings.placeholder.general": "{_esc(PLACEHOLDER_GENERAL[1])}",')
    ru_lines.append(f'    "settings.placeholder.fallback": "{_esc(PLACEHOLDER_FALLBACK[0])}",')
    en_lines.append(f'    "settings.placeholder.fallback": "{_esc(PLACEHOLDER_FALLBACK[1])}",')
    ru_lines.append(f'    "settings.help.fallback": "{_esc(HELP_FALLBACK[0])}",')
    en_lines.append(f'    "settings.help.fallback": "{_esc(HELP_FALLBACK[1])}",')

    r = _insert_keys(I18N_RU, "\n".join(ru_lines) + "\n",
                     'settings.field.dga_min_label_length', dry, force)
    e = _insert_keys(I18N_EN, "\n".join(en_lines) + "\n",
                     'settings.field.dga_min_label_length', dry, force)
    return r, e


def _patch_settings_view(dry: bool, force: bool) -> bool:
    if not SV.exists():
        return False
    text = SV.read_text(encoding="utf-8")
    original = text

    # 1. Подписи полей → tr("settings.field.<key>")
    for key in FIELD_LABELS:
        pattern = re.compile(
            r'(self\._add_\w+\(\s*form,\s*"' + re.escape(key) + r'",\s*)"[^"]*"',
        )
        text, _n = pattern.subn(
            lambda m, k=key: f'{m.group(1)}tr("settings.field.{k}")',
            text,
        )

    # 2. Placeholder: заменить _PLACEHOLDER_TEXT на динамику
    old_placeholder = (
        "        body = _PLACEHOLDER_TEXT.get(key, \"Секция в разработке.\")\n"
        "        hint = QLabel(body)\n"
    )
    new_placeholder = (
        "        body = tr(f\"settings.placeholder.{key}\")\n"
        "        if body == f\"settings.placeholder.{key}\":\n"
        "            body = tr(\"settings.placeholder.fallback\")\n"
        "        hint = QLabel(body)\n"
    )
    if old_placeholder in text:
        text = text.replace(old_placeholder, new_placeholder, 1)
    else:
        print("  [warn] settings_view.py: _placeholder_page не найден",
              file=sys.stderr)

    if text == original:
        print("  settings_view.py: изменений нет")
        return False
    try:
        ast.parse(text)
    except SyntaxError as e:
        print(f"  [error] settings_view.py: {e}", file=sys.stderr)
        return False

    if dry:
        print(f"  [dry] settings_view.py: изменён")
        return True
    _backup(SV)
    SV.write_text(text, encoding="utf-8")
    print("  settings_view.py: записан")
    return True


def _patch_field_help(dry: bool, force: bool) -> bool:
    if not FH.exists():
        return False
    text = FH.read_text(encoding="utf-8")
    original = text

    # 1. Импорт tr
    if "from paradox_gui.i18n import tr" not in text:
        anchor = "from __future__ import annotations\n"
        if anchor in text:
            text = text.replace(
                anchor,
                anchor + "\nfrom paradox_gui.i18n import tr\n",
                1,
            )

    # 2. get_field_help → tr() first
    old_get = (
        "def get_field_help(key: str) -> str:\n"
        "    text = FIELD_HELP.get(key)\n"
        "    if text:\n"
        "        return text\n"
        "    return f\"Параметр «{key}» из Config ядра. См. paradox/config.py.\"\n"
    )
    new_get = (
        "def get_field_help(key: str) -> str:\n"
        "    translated = tr(f\"settings.help.{key}\")\n"
        "    if translated != f\"settings.help.{key}\":\n"
        "        return translated\n"
        "    text = FIELD_HELP.get(key)\n"
        "    if text:\n"
        "        return text\n"
        "    return tr(\"settings.help.fallback\", key=key)\n"
    )
    if old_get in text:
        text = text.replace(old_get, new_get, 1)
    else:
        print("  [warn] field_help.py: get_field_help не найден",
              file=sys.stderr)

    # 3. get_section_help → tr() first
    old_section = (
        "def get_section_help(key: str) -> str:\n"
        "    return SECTION_HELP.get(key, \"\")\n"
    )
    new_section = (
        "def get_section_help(key: str) -> str:\n"
        "    translated = tr(f\"settings.section_help.{key}\")\n"
        "    if translated != f\"settings.section_help.{key}\":\n"
        "        return translated\n"
        "    return SECTION_HELP.get(key, \"\")\n"
    )
    if old_section in text:
        text = text.replace(old_section, new_section, 1)
    else:
        print("  [warn] field_help.py: get_section_help не найден",
              file=sys.stderr)

    if text == original:
        print("  field_help.py: изменений нет")
        return False
    try:
        ast.parse(text)
    except SyntaxError as e:
        print(f"  [error] field_help.py: {e}", file=sys.stderr)
        return False

    if dry:
        print("  [dry] field_help.py: изменён")
        return True
    _backup(FH)
    FH.write_text(text, encoding="utf-8")
    print("  field_help.py: записан")
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", "-y", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    if not args.dry_run and not args.yes:
        print(f"Добавится ключей: "
              f"{len(FIELD_LABELS)} label + {len(FIELD_HINTS)} hint + 4")
        if input("Продолжить? [y/N] ").strip().lower() not in ("y", "yes", "да"):
            return 1

    print("[1/4] paradox_gui/i18n/_ru.py")
    _patch_lang_files(args.dry_run, args.force)
    print("[2/4] paradox_gui/i18n/_en.py (совместно с _ru.py)")
    print("[3/4] paradox_gui/views/settings_view.py")
    _patch_settings_view(args.dry_run, args.force)
    print("[4/4] paradox_gui/field_help.py")
    _patch_field_help(args.dry_run, args.force)
    print()
    if args.dry_run:
        print("[dry-run] ничего не записано.")
    else:
        print("Готово. Проверь:")
        print("  python -m pytest tests/test_i18n.py -v")
        print("  python -m paradox_gui")
    return 0


if __name__ == "__main__":
    sys.exit(main())
