"""Разбор pcap в CaptureState: пакетный цикл, экстракторы, post-extract."""
from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from pathlib import Path

from paradox.config import Config
from paradox.errors import ParadoxInputError
from paradox.extractors.arp_history import ARPMacHistoryExtractor
from paradox.extractors.dhcp import DHCPExtractor
from paradox.extractors.dns import DNSExtractor
from paradox.extractors.flow import FlowExtractor
from paradox.extractors.host_identity import HostIdentityExtractor
from paradox.extractors.http import HTTPExtractor
from paradox.extractors.http_object import HTTPObjectExtractor
from paradox.extractors.kerberos import KerberosExtractor
from paradox.extractors.nbns import NBNSExtractor
from paradox.extractors.ndp import NDPExtractor
from paradox.extractors.smtp import SMTPExtractor
from paradox.extractors.ssh_banner import SSHBannerExtractor
from paradox.extractors.tls import TLSExtractor
from paradox.file_carve import carve_files
from paradox.models import CaptureState
from paradox.parsers import parse_packet
from paradox.pcap_reader import PcapFormatError, PcapRecordReader
from paradox.pipeline.errors import PipelineCancelled
from paradox.reassembler import TCPReassembler

# Порядок экстракторов важен: FlowExtractor ДОЛЖЕН идти первым,
# остальные экстракторы, пишущие в FlowStats, ищут существующий flow.
#
# Контракт: экстракторы STATELESS. Работают только через параметры
# (record, state). Между прогонами run_pipeline в одном процессе
# (важно для GUI) внутреннего мусора не остаётся.
#
# Если добавляешь stateful экстрактор (буфер, кэш, счётчик в self) —
# замени список на фабрику build_extractors() и вызывай её в _extract().
EXTRACTORS = [
    FlowExtractor(),
    DNSExtractor(),
    TLSExtractor(),
    HTTPExtractor(),
    HostIdentityExtractor(),
    ARPMacHistoryExtractor(),
    DHCPExtractor(),           # v0.9.0
    SSHBannerExtractor(),      # v0.9.0
    SMTPExtractor(),           # v0.9.0
    NBNSExtractor(),
    KerberosExtractor(),
    NDPExtractor(),
]


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def _extract(
    pcap_path: Path,
    state: CaptureState,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> str | None:
    """Разобрать pcap в state.

    Возвращает sha256 файла, если его удалось посчитать за проход
    целиком (файл прочитан до конца), иначе None — вызывающий считает
    хэш отдельно.
    """
    import sys
    import time

    if not pcap_path.is_file():
        raise ParadoxInputError(f"файл не найден: {pcap_path}")

    with pcap_path.open("rb") as probe:
        magic = probe.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        raise ParadoxInputError(
            f"{pcap_path.name}: pcapng не поддержан. "
            "Сконвертируйте в pcap: editcap -F pcap in.pcapng out.pcap"
        )

    file_size = pcap_path.stat().st_size
    last_update = time.monotonic()
    update_interval = 2.0
    start = last_update
    show_progress = sys.stdout.isatty()

    # TCP reassembly — опционально
    reassembler: TCPReassembler | None = None
    if config.tcp_reassembly_enabled:
        reassembler = TCPReassembler(
            max_bytes_per_flow=config.tcp_reassembly_max_bytes_per_flow,
            max_total_bytes=config.tcp_reassembly_max_total_bytes,
        )

    try:
        hasher = PcapRecordReader(pcap_path.open("rb"))
    except Exception as exc:
        raise ParadoxInputError(
            f"{pcap_path.name}: не удалось прочитать pcap "
            f"({type(exc).__name__}: {exc})"
        ) from exc
    reader = hasher
    try:
        for raw_data, ts in reader:
            state.packet_count += 1

            if (
                should_stop is not None
                and state.packet_count % 10_000 == 0
                and should_stop()
            ):
                raise PipelineCancelled()

            bytes_read = reader.bytes_hashed

            try:
                record = parse_packet(raw_data, ts)
            except Exception:
                state.extractor_errors["parse"] += 1
                continue

            # Reassembly до экстракторов
            if reassembler is not None:
                reassembler.feed(record)

            now = time.monotonic()
            if now - last_update >= update_interval:
                if show_progress:
                    pct = (
                        min(100.0, bytes_read * 100.0 / file_size)
                        if file_size else 0.0
                    )
                    elapsed = now - start
                    print(
                        f"\r  {pct:5.1f}%  "
                        f"{state.packet_count:>10,} packets  "
                        f"{elapsed:6.1f}s",
                        end="",
                        flush=True,
                    )
                if on_progress is not None:
                    on_progress(bytes_read, file_size)
                last_update = now

            for ex in EXTRACTORS:
                try:
                    ex.process(record, state)
                except Exception:
                    prev = state.extractor_errors[ex.name]
                    state.extractor_errors[ex.name] = prev + 1
                    if config.debug_log_extractor_errors and prev == 0:
                        logging.exception(
                            "extractor %s failed (first occurrence)",
                            ex.name,
                        )
    except PcapFormatError as exc:
        raise ParadoxInputError(
            f"{pcap_path.name}: {exc}"
        ) from exc
    finally:
        reader.close()

    # Финализация потоков
    if reassembler is not None:
        reassembler.finalize_all()
        state.tcp_streams = reassembler.all_streams()
        state.tcp_streams_total = len(state.tcp_streams)
        state.tcp_streams_truncated = reassembler.truncated_flows()

    # Post-extract: HTTP-объекты, X.509, carve. Не зависят от флага
    # reassembly напрямую: если reassembly выключен, streams пусты и
    # экстракторы ничего не найдут. Раньше они были вложены в
    # `if reassembler is not None` и молча выпадали при выключенной
    # reassembly, хотя их собственные флаги ничего не отключали.
    try:
        HTTPObjectExtractor().run_post_extract(state, config)
    except Exception:
        state.extractor_errors["http_object"] += 1

    # X.509 сертификаты из TLS-хендшейков. Требуют reassembly,
    # потому что сертификат часто больше одного TCP-сегмента.
    try:
        from paradox.extractors.tls_cert import (
            TlsCertificateExtractor,
        )
        TlsCertificateExtractor().run_post_extract(state, config)
    except Exception:
        state.extractor_errors["tls_cert"] += 1

    # SNI/JA3 из склеенных потоков: ClientHello больше одного сегмента
    # потоковый экстрактор целиком не видит.
    try:
        TLSExtractor().run_post_extract(state, config)
    except Exception:
        state.extractor_errors["tls"] += 1

    # SMB2 и LDAP: заголовки и тела часто разбиты на сегменты, поэтому
    # разбираем склеенные потоки портов 445 / 389, 3268.
    from paradox.extractors.ldap import LDAPExtractor
    from paradox.extractors.smb2 import SMB2Extractor

    try:
        SMB2Extractor().run_post_extract(state, config)
    except Exception:
        state.extractor_errors["smb2"] += 1

    try:
        LDAPExtractor().run_post_extract(state, config)
    except Exception:
        state.extractor_errors["ldap"] += 1

    # DCE/RPC: DCSync идёт BIND'ом DRSUAPI и DsGetNCChanges либо
    # прямо в TCP-потоке, либо внутри SMB2 named pipe, поэтому
    # сканируются все склеенные потоки (см. dcerpc_parse).
    from paradox.extractors.dcerpc import DCERPCExtractor

    try:
        DCERPCExtractor().run_post_extract(state, config)
    except Exception:
        state.extractor_errors["dcerpc"] += 1

    # FileCarve — метаданные payload'ов (без записи на диск по умолчанию)
    if config.file_carve_enabled:
        try:
            _carved_dir = config.output_dir / "carved"
            state.carved_files = carve_files(
                state, config, output_dir=_carved_dir,
            )
        except Exception:
            state.extractor_errors["file_carve"] += 1

    if on_progress is not None:
        on_progress(file_size, file_size)

    # Сырые байты потоков больше не нужны: HTTP-объекты, сертификаты
    # и carved-файлы уже извлечены. Без очистки state держал бы
    # до 200 МБ до конца прогона.
    state.tcp_streams.clear()

    if show_progress:
        elapsed = time.monotonic() - start
        print(
            f"\r  done: {state.packet_count:,} packets in {elapsed:.1f}s"
            + " " * 20
        )

    # Хэш валиден, только если прочитан весь файл: при обрезанном
    # хвосте (trailing garbage) отдаём None, и вызывающий пересчитает.
    if hasher.bytes_hashed == file_size:
        return hasher.hexdigest()
    return None
