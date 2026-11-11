"""DCSyncDetector — DRSUAPI DsGetNCChanges (opnum 3).

DCSync — имитация репликации контроллера домена: клиент
привязывается к интерфейсу DRSUAPI и вызывает `DsGetNCChanges`,
чтобы получить учётные записи вместе с хэшами (включая `krbtgt`).
Легитимно этот вызов делает только контроллер домена.

`DCERPCExtractor` кладёт в state только те REQUEST'ы, чей контекст
привязан к DRSUAPI, поэтому здесь достаточно opnum 3.

Ограничение: легитимная репликация между контроллерами домена
делает тот же вызов и на проводе неотличима от DCSync — DSA GUID
в запросе подделывается тривиально, поэтому на него не опираемся.
Успешный и отклонённый вызов тоже не различаем: попытка сама по
себе является сигналом. Отсюда confidence 0.7, а не 0.9: адрес
источника нужно сверить с реальными DC.
"""
from paradox.config import Config
from paradox.models import CaptureState, Finding

DCSYNC_OPNUM = 3


class DCSyncDetector:
    name = "dcsync"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        if not state.dcerpc_drsuapi_calls:
            return []

        per_pair: dict[tuple[str, str], dict] = {}
        for (client, server, port, opnum), count in (
            state.dcerpc_drsuapi_calls.items()
        ):
            if opnum != DCSYNC_OPNUM:
                continue
            bucket = per_pair.setdefault(
                (client, server), {"calls": 0, "ports": set()},
            )
            bucket["calls"] += count
            bucket["ports"].add(port)

        findings: list[Finding] = []
        for (client, server), bucket in per_pair.items():
            naming_contexts = sorted(
                naming_context
                for (src, dst, naming_context)
                in state.dcerpc_naming_contexts
                if src == client and dst == server
            )
            value = f"DsGetNCChanges ×{bucket['calls']}"
            if naming_contexts:
                value += f" ({naming_contexts[0]})"

            findings.append(Finding(
                type="dcsync",
                value=value,
                src_ip=client,
                dst_ip=server,
                dst_port=min(bucket["ports"]),
                severity="critical",
                confidence=0.7,
                evidence={
                    "opnum": DCSYNC_OPNUM,
                    "interface": "DRSUAPI",
                    "calls": bucket["calls"],
                    "ports": sorted(bucket["ports"]),
                    "naming_contexts": naming_contexts,
                },
            ))

        findings.sort(key=lambda f: (f.src_ip or "", f.dst_ip or ""))
        return findings
