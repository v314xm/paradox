"""Человеческие описания детекторов для вкладки «Детекторы».

Ключи совпадают с _DETECTORS в settings_view.py и с ключами,
которые уходят в analysis_worker через disabled_detectors.
"""
from __future__ import annotations

DETECTOR_HELP: dict[str, str] = {
    "dga":
        "Случайно сгенерированные домены (xg7f2k9vbn.com). Malware "
        "использует их для C2, чтобы обойти статические списки.",
    "port_scan":
        "Много соединений к разным портам одной цели с одного "
        "источника. Признак разведки перед атакой.",
    "suspicious_port":
        "Порты из известных наборов: 4444 (Metasploit), 31337, 1337. "
        "Часто — backdoor или pentest-инструмент.",
    "nxdomain_burst":
        "Всплеск NXDOMAIN от одного источника. DGA или malware "
        "перебирает несуществующие домены.",
    "cloud_tunnel":
        "Трафик к ngrok, trycloudflare, serveo. Туннелирование "
        "соединений через публичные сервисы.",
    "ip_check_service":
        "Обращения к ip-api.com, ifconfig.me. Malware проверяет "
        "внешний IP после заражения или в процессе C2.",
    "typosquatting":
        "Домены, похожие на известные бренды (g00gle.com). "
        "Классический фишинг.",
    "sni_mismatch":
        "SNI в TLS ClientHello не совпадает с ожидаемым доменом. "
        "Domain fronting или подмена сертификата.",
    "rare_external_ip":
        "Внутренний хост 1–2 раза сходил на внешний IP, которого нет "
        "в DNS-ответах захвата и который не назван ни SNI, ни Host. "
        "Похоже на зашитый в малварь адрес C2 без домена.",
    "long_connections":
        "TCP-сессия наружу живёт дольше 30 минут, но не представилась "
        "ни SNI, ни Host, и порт не служебный. Keepalive C2, "
        "reverse shell или туннель в одном соединении.",
    "ja3_malware":
        "Отпечаток TLS-клиента совпадает с базой malware: "
        "Cobalt Strike, Trickbot, Emotet.",
    "ja3s_malware":
        "Отпечаток TLS-сервера (ServerHello) совпадает с базой malware. "
        "Cobalt Strike, Meterpreter и др. База по умолчанию пуста — "
        "сигнал появится, если добавите свои JA3S-хеши в Config.",
    "brute_force":
        "Много HTTP-запросов к login-endpoint с одного источника. "
        "Подбор пароля через web-форму.",
    "ftp_brute_force":
        "Много FTP-сессий к одному серверу с уникальных src-портов. "
        "Подбор учётных данных FTP.",
    "beaconing":
        "Регулярные соединения к одной паре (dst, port) с малым "
        "jitter. C2-heartbeat, стучится за командами.",
    "dns_tunneling":
        "Длинные уникальные поддомены под одним базовым. Вынос "
        "данных через DNS-запросы в обход firewall.",
    "lateral_movement":
        "SMB/RDP/WinRM-трафик между внутренними хостами. "
        "Признак распространения по сети.",
    "large_transfer":
        "Большой объём данных от одного хоста. Возможная утечка "
        "или массовая загрузка.",
    "vulnerable_path":
        "Обращения к известным уязвимым путям: wp-login, /.env, "
        "/phpmyadmin, /.git/. Сканирование и эксплуатация.",
    "command_injection":
        "Паттерны RCE в HTTP (system(), os.execute, |nc). "
        "Попытка выполнения команд на сервере.",
    "http_binary_upload":
        "Серия POST'ов с бинарным телом (application/octet-stream, "
        "gzip, зашифрованный блоб) на внешний хост. Типовой канал "
        "RAT/stealer'а: выгрузка данных по случайным URI.",
    "php_payload":
        "PHP-исходник в HTTP: ответ начинается с '<?php' "
        "(php_download — скачанный веб-шелл/дроппер) или POST "
        "содержит '<?php' (webshell_upload — заливка шелла). "
        "По телу, а не по расширению: /index.php — это норма.",
    "webshell_markers":
        "Маркеры веб-шеллов разных языков: eval/assert/system/"
        "shell_exec с $_POST/$_GET, eval Request[...], "
        "Runtime.getRuntime().exec(request.getParameter), "
        "Process.Start(Request), семейства WSO/"
        "b3" "74k" "/" "c9" "9" "/" "r5" "7" "/phpspy. "
        "Ищет связку «исполнение + ввод из запроса», а не просто eval(.",
    "ssh_brute_force":
        "Много SSH-сессий к одному серверу с уникальных src-портов. Подбор "
        "учётных данных SSH: сервер видит серию неудачных аутентификаций с одного "
        "клиента за короткое окно.",
    "smtp_spam":
        "Один хост рассылает письма на множество адресов. Спам-бот, "
        "скомпрометированный аккаунт или тест рассылки. SMTP-сессия с большим "
        "числом RCPT TO на одного клиента.",
    "yara":
        "Пользовательские YARA-правила. Сигнатуры malware в захваченном payload:"
        "имя правила, теги, привязка к файлу.",
}


def get_detector_help(key: str) -> str:
    return DETECTOR_HELP.get(key, "")
