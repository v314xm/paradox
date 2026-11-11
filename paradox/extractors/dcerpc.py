"""DCERPCExtractor — DRSUAPI bind и вызовы из склеенных потоков.

DCSync идёт поверх DCE/RPC: сначала BIND интерфейса DRSUAPI
(`e3514235-4b06-11d1-ab04-00c04fc2dcd2`), затем REQUEST opnum 3
(`DsGetNCChanges`). Кадры лежат либо прямо в TCP-потоке
(`ncacn_ip_tcp`, в том числе на динамическом порту после endpoint
mapper), либо внутри SMB2 WRITE named pipe `\\drsuapi`, поэтому поток
сканируется целиком, а SMB2-конверт отдельно не разбирается.

Пишет в CaptureState: bind-ы по интерфейсам, вызовы в контексте
DRSUAPI, naming context из тел `DsGetNCChanges` и учётку из AUTH3.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.dcerpc_parse import scan_drsuapi
from paradox.models import CaptureState, HostIdentity

MAX_DISTINCT_KEYS = 500


def _bump(counter, key) -> None:
    if key in counter or len(counter) < MAX_DISTINCT_KEYS:
        counter[key] += 1


class DCERPCExtractor:
    name = "dcerpc"
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
            if key.proto != "tcp" or not stream:
                continue

            session = scan_drsuapi(stream)
            if not (session.binds or session.calls or session.identity):
                continue

            client, server = key.src_ip, key.dst_ip
            for context in session.binds:
                _bump(
                    state.dcerpc_binds,
                    (client, server, context.uuid, context.version),
                )
            for call in session.calls:
                _bump(
                    state.dcerpc_drsuapi_calls,
                    (client, server, key.dst_port, call.opnum),
                )
            for naming_context in session.naming_contexts:
                _bump(
                    state.dcerpc_naming_contexts,
                    (client, server, naming_context),
                )
            if session.identity is not None:
                domain, username, workstation = session.identity
                self._touch_identity(
                    state, client, domain, username, workstation,
                )

    @staticmethod
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
