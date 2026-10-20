"""
ARPMacHistoryExtractor — история MAC-адресов на один IP.

Отличие от HostIdentityExtractor: тот пишет только последний MAC
(для отчёта сущностей). Здесь — полная история: IP → {MAC: [first_ts,
last_ts, count]}. Нужна правилу mac_ip_conflict: ARP-spoof выглядит
как смена MAC на одном IP за короткое время, финальное значение
теряет атаку.

Фильтры те же, что в HostIdentityExtractor:
  - 0.0.0.0 (DHCP discover)
  - broadcast / multicast MAC
  - нулевой MAC

Дублирование фильтров осознанное: два экстрактора преследуют разные
цели, но валидируют один источник. Вынесение в общую функцию создаст
лишний coupling — если фильтры разойдутся (например, история захочет
логировать broadcast для правила «broadcast storm»), проще когда
у каждого свои.
"""
from paradox.models import CaptureState
from paradox.parsers import PacketRecord


class ARPMacHistoryExtractor:
    name = "arp_mac_history"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.proto != "arp":
            return
        if not record.arp_sender_ip or not record.arp_sender_mac:
            return
        self._record(
            state,
            record.arp_sender_ip,
            record.arp_sender_mac,
            record.ts if record.ts is not None else 0.0,
        )

    def _record(
        self, state: CaptureState, ip: str, mac: str, ts: float,
    ) -> None:
        # Пропускаем невалидные IP (DHCP-запросы идут с 0.0.0.0)
        if not ip or ip == "0.0.0.0":
            return
        # Пропускаем broadcast/multicast MAC
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        if mac.startswith("01:00:5e") or mac.startswith("33:33"):
            return

        per_ip = state.arp_macs.setdefault(ip, {})
        entry = per_ip.get(mac)
        if entry is None:
            # [first_ts, last_ts, count]
            per_ip[mac] = [ts, ts, 1]
        else:
            if ts < entry[0]:
                entry[0] = ts
            if ts > entry[1]:
                entry[1] = ts
            entry[2] += 1