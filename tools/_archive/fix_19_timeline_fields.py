from pathlib import Path

from fix_utils import patch

FIX_ID = "fix_19"
TITLE = "Add explicit IP fields to TimelineEvent, remove GUI regex"


def apply(root: Path) -> bool:
    changed = False

    # 1. Добавляем поля в ядро
    changed |= patch(
        root, "paradox/timeline.py",
        old="    mitre_id: str | None = None\n    ref_id: int | None = None\n\n\n@dataclass\nclass TimelineEvent:\n",
        # Ошибка была здесь? Нет, просто заменим блок
        new="    mitre_id: str | None = None\n    ref_id: int | None = None\n    src_ip: str = \"\"\n    dst_ip: str = \"\"\n    dst_port: int | None = None\n\n\n@dataclass\nclass TimelineEvent:\n",
        required=False  # Если не найдем, попробуем другой вариант
    )

    # Более точный патч для dataclass:
    changed |= patch(
        root, "paradox/timeline.py",
        old="    description: str\n    mitre_id: str | None = None\n    ref_id: int | None = None\n",
        new="    description: str\n    mitre_id: str | None = None\n    ref_id: int | None = None\n    src_ip: str = \"\"\n    dst_ip: str = \"\"\n    dst_port: int | None = None\n"
    )

    changed |= patch(
        root, "paradox/timeline.py",
        old="            \"mitre_id\": self.mitre_id,\n            \"ref_id\": self.ref_id,\n        }\n",
        new="            \"mitre_id\": self.mitre_id,\n            \"ref_id\": self.ref_id,\n            \"src_ip\": self.src_ip,\n            \"dst_ip\": self.dst_ip,\n            \"dst_port\": self.dst_port,\n        }\n"
    )

    changed |= patch(
        root, "paradox/timeline.py",
        old="        mitre_id=f.mitre_id,\n        ref_id=idx,\n    )\n",
        new="        mitre_id=f.mitre_id,\n        ref_id=idx,\n        src_ip=f.src_ip or \"\",\n        dst_ip=f.dst_ip or \"\",\n        dst_port=f.dst_port,\n    )\n"
    )

    # 2. Чистим GUI
    rel = "paradox_gui/views/timeline_view.py"
    changed |= patch(root, rel, old="import re\n\n", new="")

    changed |= patch(
        root, rel,
        old=(
            "# Паттерн для поиска связи \"IP -> IP\" (с учетом возможных пробелов вокруг стрелки)\n"
            "ARROW_REGEX = re.compile(r'((?:\\d{1,3}\\.){3}\\d{1,3})\\s*->\\s*((?:\\d{1,3}\\.){3}\\d{1,3})')\n"
            "# Просто поиск IPv4 (для fallback)\n"
            "IP_REGEX = re.compile(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b')\n"
        ),
        new="",
    )

    changed |= patch(
        root, rel,
        old=(
            "    def _extract_ips(self, text: str) -> tuple[str, str]:\n"
            "        \"\"\"Извлекает Source и Destination из текста.\"\"\"\n"
            "        # 1. Пытаемся найти четкий паттерн \"IP -> IP\"\n"
            "        match = ARROW_REGEX.search(text)\n"
            "        if match:\n"
            "            return match.group(1), match.group(2)\n"
            "\n"
            "        # 2. Если паттерна нет, берем первые два УНИКАЛЬНЫХ IP в тексте\n"
            "        ips = IP_REGEX.findall(text)\n"
            "        unique_ips = []\n"
            "        for ip in ips:\n"
            "            if ip not in unique_ips:\n"
            "                unique_ips.append(ip)\n"
            "\n"
            "        if len(unique_ips) >= 2:\n"
            "            return unique_ips[0], unique_ips[1]\n"
            "        elif len(unique_ips) == 1:\n"
            "            return unique_ips[0], \"—\"\n"
            "        return \"—\", \"—\"\n"
        ),
        new="",
    )

    changed |= patch(
        root, rel,
        old=(
            "                # Пытаемся получить полный текст события\n"
            "                full_text = f\"{e.get('subject', '')} {e.get('description', '')} {e.get('value', '')}\"\n"
            "                src_ip, dst_ip = self._extract_ips(full_text)\n"
        ),
        new=(
            "                src_ip = str(e.get(\"src_ip\") or \"—\")\n"
            "                dst_ip = str(e.get(\"dst_ip\") or \"—\")\n"
        ),
    )
    return changed
