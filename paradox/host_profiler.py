"""Профилирование хоста: базовая роль (по OUI) + наблюдение поведения.

Роль — «паспорт» хоста: кто он по MAC/OUI. Поведение — что он делает в
трафике прямо сейчас. Правило ``role_deviation`` сравнивает их: если
рабочая станция начала отвечать как веб-сервер или сервер начал
сканировать сеть — это отклонение от роли.

Намеренно без ML и без внешних данных: только словари OUI-префиксов и
эвристики по ``CaptureState.flows`` — работает на лету, в том же цикле
памяти, что и остальной анализ.

Таблица OUI намеренно малая: только узнаваемые вендоры (Apple, Samsung,
Xiaomi → клиент; VMware/QEMU/Xen → сервер; Cisco/Juniper/Huawei/... →
сетевое устройство). Незнакомый OUI → ``unknown`` — и правило молчит,
потому что сравнивать «паспорт» не с чем.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.models import CaptureState
from paradox.net_utils import is_internal_ip

# --- OUI-префиксы (первые 3 октета MAC, нижний регистр) → категория. ---

_CLIENT_OUIS: frozenset[str] = frozenset({
    # Apple
    "00:03:93", "00:0a:95", "00:1b:63", "00:25:3f", "00:25:bc",
    "3c:07:54", "a4:5e:60", "ac:bc:32", "f0:18:98", "c8:2a:14",
    "88:66:5a",
    # Samsung
    "00:1d:25", "5c:cb:99", "b0:51:8e", "cc:46:d6", "f4:f5:d8",
    "18:67:b0",
    # Xiaomi
    "28:6c:07", "64:09:80", "a4:5c:27", "f4:b8:5e", "f8:a4:5f",
    "78:11:dc",
})

_SERVER_OUIS: frozenset[str] = frozenset({
    # VMware
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",
    # QEMU / KVM (дефолтный локально-администрируемый диапазон)
    "52:54:00",
    # Xen
    "00:16:3e",
})

_NETWORK_OUIS: frozenset[str] = frozenset({
    # Cisco
    "00:00:0c", "00:01:42", "00:1b:0c", "70:81:05",
    # Juniper
    "00:05:85", "2c:21:72",
    # Huawei
    "00:e0:fc", "48:46:fb", "00:1f:64",
    # TP-Link
    "00:1d:0f", "50:c7:bf", "c0:4a:00",
    # D-Link
    "00:05:5d", "00:1b:11", "f0:7d:68",
})

_WEBSERVER_PORTS: frozenset[int] = frozenset({80, 443})
_SMB_PORT = 445


class HostProfiler:
    """Роль и поведение хоста — чистые функции от ``state``."""

    # ------------------------------------------------------------------
    # baseline role (кто хост «по паспорту»)
    # ------------------------------------------------------------------

    def mac_for(self, state: CaptureState, ip: str) -> str | None:
        """MAC хоста: из host_identities, затем из ARP-истории."""
        ident = state.host_identities.get(ip)
        if ident is not None and ident.mac:
            return ident.mac
        macs = state.arp_macs.get(ip)
        if macs:
            return sorted(macs)[0]
        return None

    @staticmethod
    def oui_of(mac: str | None) -> str | None:
        """Первые 3 октета MAC в нижнем регистре ('aa:bb:cc')."""
        if not mac:
            return None
        parts = mac.lower().split(":")
        if len(parts) < 3:
            return None
        return ":".join(parts[:3])

    def assign_role(self, state: CaptureState, config: Config, ip: str) -> str:
        """Базовая роль хоста по OUI его MAC.

        Незнакомый/отсутствующий OUI → 'unknown': без «паспорта»
        отклонение не с чем сравнивать.
        """
        oui = self.oui_of(self.mac_for(state, ip))
        if oui in _CLIENT_OUIS:
            return "workstation"
        if oui in _SERVER_OUIS:
            return "server"
        if oui in _NETWORK_OUIS:
            return "network_device"
        return "unknown"

    def role_evidence(self, state: CaptureState, ip: str) -> dict:
        """Сигналы, по которым присвоена роль (для факта и отчёта)."""
        ident = state.host_identities.get(ip)
        mac = self.mac_for(state, ip)
        return {
            "mac": mac,
            "oui": self.oui_of(mac),
            "hostnames": sorted(ident.hostnames) if ident else [],
            "username": ident.username if ident else None,
        }

    # ------------------------------------------------------------------
    # behavioral observation (что хост делает сейчас)
    # ------------------------------------------------------------------

    def observe_behaviors(
        self,
        state: CaptureState,
        config: Config,
        ip: str,
    ) -> dict[str, dict]:
        """Текущее поведение хоста: behavior → evidence.

        Детектирует:
          acting_as_webserver — хост отдавал данные на порту 80/443
              (он источник, src_port = 80/443, суммарно >= min_bytes);
          acting_as_smb_server — то же на 445;
          acting_as_scanner   — инициировал SYN к >= min_targets пар
              (dst_ip, dst_port) на >= min_ports разных портах. Критерий
              «разные порты» отличает сканер от браузера, который ходит
              на сотни IP, но на один-два порта.
        """
        served: dict[int, int] = {}
        targets: set[tuple[str, int]] = set()
        dst_ports: set[int] = set()
        first_ts: float | None = None

        for key, flow in state.flows.items():
            if key.src_ip != ip:
                continue
            if key.src_port in _WEBSERVER_PORTS:
                served[key.src_port] = served.get(key.src_port, 0) + flow.bytes_sent
            if key.src_port == _SMB_PORT:
                served[_SMB_PORT] = served.get(_SMB_PORT, 0) + flow.bytes_sent
            if key.proto == "tcp" and key.dst_port is not None:
                targets.add((key.dst_ip, key.dst_port))
                dst_ports.add(key.dst_port)
            if flow.first_ts is not None:
                if first_ts is None or flow.first_ts < first_ts:
                    first_ts = flow.first_ts

        out: dict[str, dict] = {}
        min_bytes = config.role_server_min_bytes

        web_bytes = sum(served.get(p, 0) for p in _WEBSERVER_PORTS)
        if web_bytes >= min_bytes:
            out["acting_as_webserver"] = {
                "served_bytes": web_bytes,
                "ports": sorted(p for p in _WEBSERVER_PORTS if served.get(p, 0)),
                "first_ts": first_ts,
            }

        smb_bytes = served.get(_SMB_PORT, 0)
        if smb_bytes >= min_bytes:
            out["acting_as_smb_server"] = {
                "served_bytes": smb_bytes,
                "ports": [_SMB_PORT],
                "first_ts": first_ts,
            }

        if (
            len(targets) >= config.role_scanner_min_targets
            and len(dst_ports) >= config.role_scanner_min_ports
        ):
            out["acting_as_scanner"] = {
                "targets": len(targets),
                "distinct_ports": len(dst_ports),
                "first_ts": first_ts,
            }

        return out


def internal_hosts(state: CaptureState, config: Config) -> set[str]:
    """Внутренние IP из flows + host_identities + ARP-истории."""
    ips: set[str] = set()
    for key in state.flows:
        if is_internal_ip(key.src_ip, config):
            ips.add(key.src_ip)
        if is_internal_ip(key.dst_ip, config):
            ips.add(key.dst_ip)
    ips.update(state.host_identities.keys())
    ips.update(state.arp_macs.keys())
    return ips
