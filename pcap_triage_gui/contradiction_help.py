"""Описания правил ContradictionDetector.

Ключи совпадают с _CONTRADICTIONS в settings_view.py и с
type(rule).__name__ в analysis_worker.
"""
from __future__ import annotations

CONTRADICTION_HELP: dict[str, str] = {
    "VictimMakesAttackRule":
        "Хост, на который была атака, сам начинает атаковать. "
        "Признак pivot: жертву скомпрометировали.",
    "MacIpConflictRule":
        "Один MAC-адрес отвечает с разных IP. ARP-spoofing: "
        "перехват трафика в локальной сети.",
    "SniHostMismatchRule":
        "SNI в TLS не совпадает с HTTP Host. Domain fronting — "
        "обход блокировок или маскировка C2.",
    "Ja3UaMismatchRule":
        "Отпечаток TLS-клиента не соответствует User-Agent. "
        "UA подделан: клиент выдаёт себя за другого.",
    "ReverseAsymmetryRule":
        "Резкий перекос трафика в одну сторону. Эксфильтрация "
        "или односторонний C2-канал.",
    "PortServiceMismatchRule":
        "На стандартном порту — нестандартный протокол. "
        "Туннелирование (SSH на 443, HTTP на 22).",
    "DirectIpNoDnsRule":
        "Обращение к внешнему IP без DNS-запроса в захвате. "
        "Hardcoded C2 или обращение в обход резолва.",
    "SniWithoutDnsRule":
        "TLS SNI есть, а DNS-запроса к этому домену — нет. "
        "Домен захардкожен в malware или DoH.",
    "DnsAnswerMismatchRule":
        "DNS-ответ не совпадает с содержимым трафика. "
        "DNS-hijacking или MITM.",
    "SniCertMismatchRule":
        "CN/SAN сертификата не совпадает с SNI. Сертификат "
        "выдан другому домену — подмена.",
    "SelfSignedCertRule":
        "Самоподписанный сертификат на внешнем сервисе. "
        "Стандарт для тестов, но и признак C2-инфраструктуры.",
    "ExpiredCertRule":
        "Просроченный сертификат на внешнем сервисе. "
        "Халатность или C2-инфраструктура без обслуживания.",
}


def get_contradiction_help(key: str) -> str:
    return CONTRADICTION_HELP.get(key, "")
