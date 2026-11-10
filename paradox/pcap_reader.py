"""Минимальный последовательный читатель pcap.

Зачем не scapy.utils.RawPcapReader: на 627k пакетов его обвязка
(проверки, namedtuple метаданных, read/tell на каждый пакет) занимает
около 18% времени разбора. Формат pcap для чтения простой: 24-байтный
глобальный заголовок и записи «16 байт заголовка + данные».

Поддержаны оба порядка байт и микро/наносекунды. pcapng и «modified
pcap» (магия 0xa1b2cd34) не читаются — pcapng отсекается в pipeline
раньше с подсказкой про editcap.

Класс считает sha256 прочитанного за тот же проход (bytes_hashed и
hexdigest), поэтому второй проход по файлу для provenance не нужен.
"""
from __future__ import annotations

import hashlib
import struct

# magic → (порядок байт, наносекунды)
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}

_GLOBAL_HEADER_LEN = 24
_RECORD_HEADER_LEN = 16
_HASH_CHUNK = 64 * 1024


class PcapFormatError(ValueError):
    """Файл не является поддерживаемым pcap или оборван посередине."""


class PcapRecordReader:
    """Итератор `(raw_bytes, timestamp)` по записям pcap."""

    def __init__(self, stream) -> None:
        self._stream = stream
        self._hash = hashlib.sha256()
        self._pending = bytearray()
        self.bytes_hashed = 0
        self.complete = False

        header = self._read_exact(_GLOBAL_HEADER_LEN)
        magic = header[:4]
        if magic not in _MAGICS:
            raise PcapFormatError(
                f"неизвестная сигнатура pcap: {magic.hex()}"
            )
        endian, self.nano = _MAGICS[magic]
        self._record = struct.Struct(endian + "IIII")
        self.linktype = struct.unpack_from(endian + "I", header, 20)[0]
        self._update_hash(header)

    def __iter__(self) -> PcapRecordReader:
        return self

    def __next__(self) -> tuple[bytes, float]:
        header = self._stream.read(_RECORD_HEADER_LEN)
        if not header:
            self.complete = True
            self._flush_hash()
            raise StopIteration
        if len(header) < _RECORD_HEADER_LEN:
            # Хвостовой мусор: запись не начинается. Пакетов больше
            # нет, а хэш остаётся неполным — pipeline пересчитает его
            # вторым проходом.
            raise StopIteration

        sec, frac, incl_len, _orig_len = self._record.unpack(header)
        self._update_hash(header)
        if incl_len == 0:
            return b"", sec + frac / (1e9 if self.nano else 1e6)

        # Горячий путь: read обычно отдаёт запись целиком, поэтому
        # не зовём отдельный _read_exact на каждый пакет.
        data = self._stream.read(incl_len)
        if len(data) < incl_len:
            data = b"".join([data, self._read_exact(incl_len - len(data))])
        self._update_hash(data)
        return data, sec + frac / (1e9 if self.nano else 1e6)

    def _update_hash(self, data: bytes) -> None:
        # sha256.update на 627k мелких кусков дороже, чем на ~64 КБ:
        # копим в bytearray и сбрасываем пачками.
        self._pending += data
        self.bytes_hashed += len(data)
        if len(self._pending) >= _HASH_CHUNK:
            self._flush_hash()

    def _flush_hash(self) -> None:
        if self._pending:
            self._hash.update(self._pending)
            self._pending.clear()

    def hexdigest(self) -> str:
        self._flush_hash()
        return self._hash.hexdigest()

    def _read_exact(self, size: int) -> bytes:
        data = self._stream.read(size)
        if len(data) == size:
            return data
        chunks = [data]
        missing = size - len(data)
        while missing > 0:
            more = self._stream.read(missing)
            if not more:
                raise PcapFormatError(
                    "pcap оборван: не хватает данных записи"
                )
            chunks.append(more)
            missing -= len(more)
        return b"".join(chunks)

    def close(self) -> None:
        self._stream.close()
