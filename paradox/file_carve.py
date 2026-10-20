"""
FileCarve — извлечение метаданных о payload'ах из HTTP-ответов.

ВАЖНО: этот модуль НЕ сохраняет содержимое body на диск. Только
метаданные: SHA256, размер, MIME, URI, первые 64 байта в hex.

Причины:
- Машина аналитика не должна получать malware samples без явного
  согласия. Запуск .exe/.ps1/.sh на рабочей ОС = инцидент.
- Антивирус может сработать, карантинить, спамить алерты.
- SHA256 достаточно: ищется в VirusTotal, коррелирует с другими
  pcap, попадает в отчёты и STIX.

Если нужно тело — используй флаг file_carve_write_body=True
(по умолчанию False). Тогда body сохранится как <sha256>.bin
(не .exe), в отдельный каталог, с предупреждением в CLI.

Не сохраняем/не считаем payload'ом:
- HTML, CSS, JS, JSON, XML — контент страниц.
- Картинки, шрифты — графика.
- Файлы меньше min_size (по умолчанию 1 КБ).
- Файлы больше max_size (50 МБ — защита от гигабайтных).
"""
import hashlib
from dataclasses import dataclass
from pathlib import Path

from paradox.config import Config
from paradox.http_object import HttpObject
from paradox.models import CaptureState

_MIME_TO_EXT = {
    "application/x-dosexec": ".exe",
    "application/x-msdownload": ".exe",
    "application/x-msdos-program": ".exe",
    "application/vnd.microsoft.portable-executable": ".exe",
    "application/x-elf": ".elf",
    "application/x-executable": ".elf",
    "application/zip": ".zip",
    "application/x-7z-compressed": ".7z",
    "application/x-rar-compressed": ".rar",
    "application/java-archive": ".jar",
    "application/pdf": ".pdf",
    "application/vnd.ms-cab-compressed": ".cab",
    "application/x-shockwave-flash": ".swf",
    "text/x-shellscript": ".sh",
    "text/x-sh": ".sh",
    "application/x-sh": ".sh",
    "text/x-python": ".py",
    "text/x-powershell": ".ps1",
}

_SKIP_MIMES = {
    "text/html", "text/css", "application/json",
    "application/xml", "text/xml", "application/javascript",
    "text/javascript", "text/plain",
    "image/png", "image/jpeg", "image/gif", "image/webp",
    "image/svg+xml", "font/woff", "font/woff2",
    "application/font-woff", "application/vnd.ms-fontobject",
}

_MAGIC = [
    (b"MZ", ".exe"),
    (b"\x7fELF", ".elf"),
    (b"PK\x03\x04", ".zip"),
    (b"%PDF", ".pdf"),
    (b"\x1f\x8b", ".gz"),
    (b"7z\xbc\xaf\x27\x1c", ".7z"),
    (b"Rar!\x1a\x07", ".rar"),
    (b"\xca\xfe\xba\xbe", ".class"),
    (b"#!", ".sh"),
]


@dataclass
class CarvedFile:
    """Метаданные payload'а. Никакого body в памяти после возврата."""
    sha256: str
    ext: str
    size: int
    content_type: str | None
    src_ip: str
    dst_ip: str
    uri: str | None
    host: str | None
    first_bytes_hex: str        # первые 64 байта (для сигнатурного анализа)
    truncated: bool
    saved_path: str | None = None  # None если write_body=False
    # v0.9.0: timestamp первого flow, в котором пришёл этот payload.
    # Нужно timeline для сортировки. None если flow уже удалён или
    # не имел first_ts (теоретически).
    first_ts: float | None = None

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "ext": self.ext,
            "size": self.size,
            "content_type": self.content_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "uri": self.uri,
            "host": self.host,
            "first_bytes_hex": self.first_bytes_hex,
            "truncated": self.truncated,
            "saved_path": self.saved_path,
            "first_ts": self.first_ts,
        }


def _detect_ext(obj: HttpObject, body: bytes) -> str | None:
    """Расширение по MIME + magic. None — не payload."""
    ct = (obj.headers or {}).get("content-type", "").lower()
    ct = ct.split(";", 1)[0].strip()

    if ct in _SKIP_MIMES:
        return None

    if ct in _MIME_TO_EXT:
        return _MIME_TO_EXT[ct]

    for magic, ext in _MAGIC:
        if body.startswith(magic):
            return ext

    return None


def carve_files(
    state: CaptureState,
    config: Config,
    output_dir: Path | None = None,
) -> list[CarvedFile]:
    """
    Собрать метаданные payload'ов из HTTP-ответов.

    output_dir — если задан И config.file_carve_write_body=True,
    body сохраняется как <sha256>.bin в output_dir. Иначе
    output_dir игнорируется, файлы не создаются.
    """
    min_size = config.file_carve_min_size
    max_size = config.file_carve_max_size
    write_body = getattr(config, "file_carve_write_body", False)

    saved_dir: Path | None = None
    if write_body and output_dir is not None:
        saved_dir = Path(output_dir)
        saved_dir.mkdir(parents=True, exist_ok=True)

    carved: list[CarvedFile] = []
    seen_hashes: set[str] = set()

    for key, obj in (state.http_objects or []):
        if obj.kind != "response":
            continue
        if not obj.body:
            continue
        if len(obj.body) < min_size or len(obj.body) > max_size:
            continue

        ext = _detect_ext(obj, obj.body)
        if ext is None:
            continue

        sha = hashlib.sha256(obj.body).hexdigest()
        if sha in seen_hashes:
            continue
        seen_hashes.add(sha)

        saved_path: str | None = None
        if saved_dir is not None:
            # .bin — не .exe/.ps1: ОС не выполнит, антивирус реже сработает
            p = saved_dir / f"{sha}.bin"
            try:
                p.write_bytes(obj.body)
                saved_path = str(p)
            except OSError:
                saved_path = None

        # v0.9.0: ts из flow, в котором пришёл ответ.
        flow = state.flows.get(key)
        first_ts = flow.first_ts if flow is not None else None

        carved.append(CarvedFile(
            sha256=sha,
            ext=ext,
            size=len(obj.body),
            content_type=(obj.headers or {}).get("content-type"),
            src_ip=key.src_ip,
            dst_ip=key.dst_ip,
            uri=obj.uri,
            host=(obj.headers or {}).get("host"),
            first_bytes_hex=obj.body[:64].hex(),
            truncated=obj.truncated,
            saved_path=saved_path,
            first_ts=first_ts,
        ))

    return carved
