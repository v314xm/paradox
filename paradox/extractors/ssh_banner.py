"""
SSH banner экстрактор (RFC 4253).

SSH-сервер и клиент обмениваются идентификационными строками
сразу после установки TCP-сессии:

    SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5<CR><LF>
    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4<CR><LF>

Парсим эти строки, пишем в CaptureState:
  ssh_server_versions[(ip, port)] = software version
  ssh_client_versions[ip] = {software versions}

Свой парсер, без scapy: баннер — ASCII до первой LF.
"""
from __future__ import annotations

from paradox.models import CaptureState
from paradox.parsers import PacketRecord


# Порты, на которых ожидаем SSH-сервер. Клиент обычно на эфемерном.
SSH_SERVER_PORTS = frozenset({22, 2222, 2022})

# Максимум символов для баннера. По RFC — 255, но реально < 100.
_MAX_BANNER_LEN = 255


def parse_ssh_banner(payload: bytes) -> str | None:
    """
    Разобрать SSH-баннер из первых байт payload.

    Возвращает software version (без "SSH-2.0-" префикса и без
    trailing CR/LF). None если payload не начинается с "SSH-".

    Формат баннера: SSH-<protover>-<software> [comments]
    protover — N.N (2.0, 1.99, 1.5). software — до конца строки.
    """
    if not payload or not payload.startswith(b"SSH-"):
        return None

    # Берём до первой LF, но не более _MAX_BANNER_LEN.
    chunk = payload[:_MAX_BANNER_LEN]
    newline = chunk.find(b"\n")
    if newline != -1:
        chunk = chunk[:newline]
    # Отрезаем возможный CR в конце.
    line = chunk.rstrip(b"\r").decode("ascii", errors="ignore")
    if not line:
        return None

    parts = line.split("-", 2)
    if len(parts) < 3:
        return None
    if parts[0] != "SSH":
        return None
    # parts[1] — protover, parts[2] — software + optional comments.
    software = parts[2].strip()
    # Отсекаем возможные управляющие символы (KEXINIT прилип).
    software = "".join(c for c in software if c.isprintable())
    return software or None


class SSHBannerExtractor:
    """
    SSH banner экстрактор. Работает поверх PacketRecord.

    Логика:
      1. Payload начинается с "SSH-" — иначе не SSH.
      2. Если src_port в SSH_SERVER_PORTS — отправитель сервер.
      3. Иначе, если dst_port в SSH_SERVER_PORTS — отправитель клиент.
      4. Иначе — нестандартный порт, пропускаем.
    """
    name = "ssh_banner"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if not record.payload:
            return
        if not record.payload.startswith(b"SSH-"):
            return

        software = parse_ssh_banner(record.payload)
        if not software:
            return

        src_port = record.src_port
        dst_port = record.dst_port

        if src_port in SSH_SERVER_PORTS:
            if record.src_ip and src_port is not None:
                state.ssh_server_versions[(record.src_ip, src_port)] = software
        elif dst_port in SSH_SERVER_PORTS:
            if record.src_ip:
                state.ssh_client_versions.setdefault(
                    record.src_ip, set(),
                ).add(software)
                # v0.9.0: считаем попытки подключения. Один баннер =
                # одна сессия (RFC 4253). Ключ (src, dst, dst_port) —
                # для детектора ssh_brute_force.
                if record.dst_ip and dst_port is not None:
                    key = (record.src_ip, record.dst_ip, dst_port)
                    state.ssh_client_attempts[key] = (
                        state.ssh_client_attempts.get(key, 0) + 1
                    )
