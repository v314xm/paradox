"""SMB2Extractor — сообщения SMB2 из склеенных потоков порта 445.

Не обычный per-packet экстрактор: работает post-extract, потому что
SMB2-заголовок и тело часто разбиты на несколько TCP-сегментов.

Пишет в CaptureState агрегаты (команды, диалекты, share, пути,
ошибки статуса, объёмы) и обновляет host_identities клиента по
NTLMSSP Type 3: username, realm (домен), hostname (рабочая станция).
"""
from __future__ import annotations

from paradox.config import Config
from paradox.models import CaptureState, HostIdentity
from paradox.smb2_parse import parse_smb2_messages

MAX_DISTINCT_KEYS = 500

STATUS_PENDING = 0x00000103


def _bump(counter, key) -> None:
    """Инкремент с потолком на число разных ключей (память)."""
    if key in counter or len(counter) < MAX_DISTINCT_KEYS:
        counter[key] += 1


def _touch_identity(
    state: CaptureState,
    client_ip: str,
    domain: str | None,
    username: str | None,
    workstation: str | None,
) -> None:
    if not (domain or username or workstation):
        return
    ident = state.host_identities.get(client_ip)
    if ident is None:
        ident = HostIdentity(ip=client_ip)
        state.host_identities[client_ip] = ident
    if username and ident.username is None:
        ident.username = username
    if workstation:
        ident.hostnames.add(workstation)
    realm = domain or ""
    if realm and (ident.realm is None or (
        "." in realm and "." not in ident.realm
    )):
        ident.realm = realm


class SMB2Extractor:
    name = "smb2"
    layer = 1

    def process(self, record, state: CaptureState) -> None:
        """Per-packet обработка не нужна — no-op."""
        return

    def run_post_extract(
        self,
        state: CaptureState,
        config: Config,
    ) -> None:
        if not state.tcp_streams:
            return

        for key, stream in state.tcp_streams.items():
            if key.proto != "tcp":
                continue
            if key.dst_port != 445 and key.src_port != 445:
                continue
            if not stream:
                continue

            if key.dst_port == 445:
                client, server = key.src_ip, key.dst_ip
            else:
                client, server = key.dst_ip, key.src_ip

            messages, errors = parse_smb2_messages(stream)
            state.smb2_parse_errors += errors

            for message in messages:
                state.smb2_messages += 1
                state.smb2_commands[message.command] += 1
                if message.dialect:
                    _bump(state.smb2_dialects, message.dialect)
                if (
                    message.is_response
                    and message.status not in (0, STATUS_PENDING)
                ):
                    _bump(
                        state.smb2_status_errors,
                        f"0x{message.status:08X}",
                    )
                if message.share:
                    _bump(
                        state.smb2_shares,
                        (client, server, message.share),
                    )
                if message.path:
                    _bump(
                        state.smb2_paths,
                        (client, server, message.path),
                    )
                state.smb2_read_bytes += message.read_bytes
                state.smb2_write_bytes += message.write_bytes
                _touch_identity(
                    state, client, message.domain,
                    message.username, message.workstation,
                )
