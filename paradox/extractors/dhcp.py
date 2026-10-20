"""
DHCP-экстрактор (UDP 67/68).

Извлекает связь IP ↔ MAC ↔ hostname из DHCP-сообщений.
Дополняет ARP-based HostIdentityExtractor: ARP даёт MAC,
DHCP — ещё и hostname (опция 12).

Формат BOOTP/DHCP (RFC 2131) фиксированный, парсим struct'ом.
Scapy не используем: скорость и контроль над форматом важнее.

Протокол:
  Клиент → сервер: 68 → 67 (src_port=68, dst_port=67)
  Сервер → клиент: 67 → 68
  Обе стороны обрабатываются одинаково — просто смотрим payload.

Что пишет:
  state.host_identities[ip].mac      из chaddr
  state.host_identities[ip].hostnames из опции 12

Приоритет IP: yiaddr (выданный сервером) → ciaddr (клиент).
Если оба 0.0.0.0 — пропускаем (DISCOVER без offer ещё).
"""
from __future__ import annotations

import struct

from paradox.models import CaptureState, HostIdentity
from paradox.parsers import PacketRecord


# Магический cookie BOOTP/DHCP. Опции начинаются после него.
_DHCP_MAGIC = b"\x63\x82\x53\x63"

# Минимальная длина BOOTP-пакета до опций: 236 байт заголовок
# + 4 байта magic = 240.
_MIN_LEN = 240

# Опция Host Name (RFC 2132, раздел 3.14).
_OPT_HOSTNAME = 12

# DHCP Message Type (RFC 2132, раздел 9.6).
_OPT_MSG_TYPE = 53

# Конец списка опций.
_OPT_END = 255

# Padding между опциями.
_OPT_PAD = 0


def _ip_str(raw: bytes) -> str:
    """4 байта → 'a.b.c.d'."""
    return ".".join(str(b) for b in raw)


def _mac_str(raw: bytes, length: int) -> str:
    """Первые length байт → 'aa:bb:cc:dd:ee:ff'. Пустая строка если 0."""
    if length <= 0 or length > 16:
        return ""
    mac_bytes = raw[:length]
    if not any(mac_bytes):
        return ""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def parse_dhcp(payload: bytes) -> dict | None:
    """
    Разобрать BOOTP/DHCP payload. None если это не DHCP.

    Возвращает dict с полями:
      op, htype, hlen, xid, ciaddr, yiaddr, siaddr, giaddr,
      chaddr, msg_type, hostname.
    """
    if len(payload) < _MIN_LEN:
        return None

    # Заголовок BOOTP: фиксированные смещения (RFC 2131, раздел 2).
    op = payload[0]
    htype = payload[1]
    hlen = payload[2]
    # payload[3] = hops, не нужен
    xid = struct.unpack(">I", payload[4:8])[0]

    ciaddr = _ip_str(payload[12:16])
    yiaddr = _ip_str(payload[16:20])
    siaddr = _ip_str(payload[20:24])
    giaddr = _ip_str(payload[24:28])

    chaddr_raw = payload[28:44]  # 16 байт
    chaddr = _mac_str(chaddr_raw, hlen)

    # Magic cookie — признак DHCP. Без него BOOTP, без опций.
    if payload[236:240] != _DHCP_MAGIC:
        return None

    # Парсинг опций TLV.
    hostname: str | None = None
    msg_type: int | None = None

    i = _MIN_LEN
    while i < len(payload):
        code = payload[i]
        if code == _OPT_END:
            break
        if code == _OPT_PAD:
            i += 1
            continue
        if i + 1 >= len(payload):
            break
        length = payload[i + 1]
        if i + 2 + length > len(payload):
            break
        value = payload[i + 2:i + 2 + length]

        if code == _OPT_HOSTNAME and value:
            try:
                decoded = value.decode("ascii", errors="ignore")
                decoded = decoded.strip("\x00").strip()
                if decoded:
                    hostname = decoded
            except Exception:
                pass
        elif code == _OPT_MSG_TYPE and value:
            msg_type = value[0]

        i += 2 + length

    return {
        "op": op,
        "htype": htype,
        "hlen": hlen,
        "xid": xid,
        "ciaddr": ciaddr,
        "yiaddr": yiaddr,
        "siaddr": siaddr,
        "giaddr": giaddr,
        "chaddr": chaddr,
        "msg_type": msg_type,
        "hostname": hostname,
    }


class DHCPExtractor:
    """
    DHCP-экстрактор. Работает поверх PacketRecord.

    UDP 67/68. Проверяем только порты, не proto — proto фильтруется
    на уровне парсера, а UDP-порты уже однозначно идентифицируют
    DHCP-трафик.
    """
    name = "dhcp"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.src_port not in (67, 68) and record.dst_port not in (67, 68):
            return
        if not record.payload:
            return

        info = parse_dhcp(record.payload)
        if info is None:
            return

        # Выбираем IP клиента.
        client_ip = None
        if info["yiaddr"] and info["yiaddr"] != "0.0.0.0":
            client_ip = info["yiaddr"]
        elif info["ciaddr"] and info["ciaddr"] != "0.0.0.0":
            client_ip = info["ciaddr"]
        if not client_ip:
            return

        ident = state.host_identities.get(client_ip)
        if ident is None:
            ident = HostIdentity(ip=client_ip)
            state.host_identities[client_ip] = ident

        if info["chaddr"]:
            ident.mac = info["chaddr"]
        if info["hostname"]:
            ident.hostnames.add(info["hostname"])
