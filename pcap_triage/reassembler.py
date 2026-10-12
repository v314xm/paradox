"""
TCP reassembler.

Задача: склеить TCP-сегменты одного направления в непрерывный поток
байт. Работает по sequence numbers.

Как это работает:
- SYN-пакет (флаг 0x02, без ACK 0x10) — фиксирует базовый seq.
- Data-пакет — offset = (tcp_seq - syn_seq) mod 2^32.
  Payload сохраняется в буфер по offset.
- Out-of-order — буфер упорядочивается по offset перед склейкой.
- Retransmit — если offset уже занят, сегмент игнорируется (первый
  пришедший считается верным).
- FIN (0x01) или RST (0x04) — поток финализируется.
- Конец захвата — всё, что осталось в буферах, финализируется
  принудительно.

Ограничения:
- Только TCP. UDP не поддерживает reassembly.
- IPv4 только (parser не умеет IPv6).
- Overlapping segments с разными данными — игнорируются (берём
  первый). В норме такого не бывает.
- Память: per-flow 1 МБ, total 200 МБ (параметры в Config).
  При превышении поток помечается truncated и его данные теряются.
"""
from pcap_triage.models import FlowKey
from pcap_triage.parsers import PacketRecord


_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_ACK = 0x10

_UINT32_MASK = 0xFFFFFFFF


class TCPReassembler:
    def __init__(
        self,
        max_bytes_per_flow: int = 1024 * 1024,
        max_total_bytes: int = 200 * 1024 * 1024,
    ):
        self.max_bytes_per_flow = max_bytes_per_flow
        self.max_total_bytes = max_total_bytes

        # key -> {offset -> payload}
        self._buffers: dict[FlowKey, dict[int, bytes]] = {}
        # key -> базовый seq (из SYN или первого пакета)
        self._syn_seq: dict[FlowKey, int] = {}
        # key -> размер буфера (для быстрой проверки лимита)
        self._flow_sizes: dict[FlowKey, int] = {}
        # финализированные потоки
        self._finalized: dict[FlowKey, bytes] = {}
        # потоки, которые не влезли в лимит
        self._truncated: set[FlowKey] = set()
        # общий счётчик байт (в буферах + финализированных)
        self._total_bytes = 0

    def feed(self, record: PacketRecord) -> None:
        """Принять пакет. Обрабатываются только TCP с известным seq."""
        if record.proto != "tcp":
            return
        if record.src_ip is None or record.dst_ip is None:
            return
        if record.tcp_seq is None:
            return

        key = FlowKey(
            proto="tcp",
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
        )

        flags = record.tcp_flags or 0

        # Новый сеанс — SYN без ACK
        if (flags & _TCP_SYN) and not (flags & _TCP_ACK):
            self._syn_seq[key] = record.tcp_seq

        # Payload (может быть вместе с FIN)
        if record.payload:
            base = self._syn_seq.get(key)
            if base is None:
                # mid-stream: первое увиденное seq принимаем за базу
                base = record.tcp_seq
                self._syn_seq[key] = base

            offset = (record.tcp_seq - base) & _UINT32_MASK
            self._store(key, offset, record.payload)

        # Конец направления — FIN или RST
        if flags & (_TCP_FIN | _TCP_RST):
            self._finalize(key)

    def _store(self, key: FlowKey, offset: int, data: bytes) -> None:
        # Уже финализирован — поздние retransmit игнорируем
        if key in self._finalized:
            return

        # Общий лимит памяти
        if self._total_bytes >= self.max_total_bytes:
            self._truncated.add(key)
            return

        buf = self._buffers.setdefault(key, {})

        # Retransmit — offset уже занят
        if offset in buf:
            return

        # Per-flow лимит
        flow_size = self._flow_sizes.get(key, 0)
        if flow_size + len(data) > self.max_bytes_per_flow:
            self._truncated.add(key)
            return

        buf[offset] = data
        self._flow_sizes[key] = flow_size + len(data)
        self._total_bytes += len(data)

    def _finalize(self, key: FlowKey) -> None:
        if key in self._finalized:
            return
        buf = self._buffers.pop(key, None)
        self._flow_sizes.pop(key, None)
        self._syn_seq.pop(key, None)
        if not buf:
            return
        offsets = sorted(buf.keys())
        data = b"".join(buf[o] for o in offsets)
        self._finalized[key] = data

    def finalize_all(self) -> None:
        """Склеить все незакрытые потоки (конец захвата)."""
        for key in list(self._buffers.keys()):
            self._finalize(key)

    def all_streams(self) -> dict[FlowKey, bytes]:
        return dict(self._finalized)

    def truncated_flows(self) -> set[FlowKey]:
        return set(self._truncated)

    def stats(self) -> dict:
        return {
            "streams_total": len(self._finalized),
            "streams_truncated": len(self._truncated),
            "bytes_total": self._total_bytes,
        }