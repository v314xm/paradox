"""LDAPExtractor — bind/search из склеенных потоков LDAP.

Порты 389 (LDAP) и 3268 (Global Catalog). LDAPS (636) зашифрован и
сюда не попадает.

Пишет в CaptureState агрегаты: bind DN, base DN, текстовые фильтры,
запрошенные атрибуты и коды результата. Из bind DN достаёт username
и realm (dc=...) в host_identities клиента.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.ldap_parse import parse_ldap_messages
from paradox.models import CaptureState, HostIdentity
from paradox.taxonomy import AD_RECON_ATTRIBUTES

LDAP_PORTS = frozenset({389, 3268})
MAX_DISTINCT_KEYS = 500


def _bump(counter, key) -> None:
    if key in counter or len(counter) < MAX_DISTINCT_KEYS:
        counter[key] += 1


def _rdn_value(dn: str, names: tuple[str, ...]) -> str | None:
    """Первое значение RDN вида ``CN=Иван,OU=...``."""
    first = dn.split(",", 1)[0] if dn else ""
    if "=" not in first:
        return None
    key, _, value = first.partition("=")
    if key.strip().lower() not in names:
        return None
    return value.strip() or None


def _realm_from_dn(dn: str) -> str | None:
    """``CN=x,DC=corp,DC=local`` → ``corp.local``."""
    parts = [
        part.split("=", 1)[1].strip()
        for part in dn.split(",")
        if part.strip().lower().startswith("dc=") and "=" in part
    ]
    return ".".join(part for part in parts if part) or None


class LDAPExtractor:
    name = "ldap"
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
            if (
                key.dst_port not in LDAP_PORTS
                and key.src_port not in LDAP_PORTS
            ):
                continue
            if not stream:
                continue

            client = (
                key.src_ip if key.dst_port in LDAP_PORTS else key.dst_ip
            )
            messages, errors = parse_ldap_messages(stream)
            state.ldap_parse_errors += errors

            for message in messages:
                state.ldap_messages += 1
                if message.bind_dn is not None:
                    bind_dn = message.bind_dn or "(anonymous)"
                    _bump(state.ldap_bind_dns, bind_dn)
                    self._touch_identity(state, client, bind_dn)
                if message.base_dn is not None:
                    _bump(state.ldap_search_bases, message.base_dn)
                    _bump(state.ldap_searches_by_src, client)
                    filter_text = (message.filter or "").lower()
                    if (
                        message.base_dn == ""
                        and "objectclass=*" in filter_text
                    ):
                        _bump(state.ldap_root_dse_by_src, client)
                    wanted = {
                        attr.lower() for attr in message.attributes
                    } & AD_RECON_ATTRIBUTES
                    if wanted:
                        state.ldap_sensitive_attrs_by_src.setdefault(
                            client, set(),
                        ).update(wanted)
                if message.filter:
                    _bump(state.ldap_filters, message.filter)
                for attribute in message.attributes:
                    _bump(state.ldap_attributes, attribute)
                if message.result_code is not None:
                    _bump(
                        state.ldap_result_codes,
                        str(message.result_code),
                    )

    @staticmethod
    def _touch_identity(
        state: CaptureState,
        client_ip: str,
        bind_dn: str,
    ) -> None:
        username = _rdn_value(
            bind_dn, ("cn", "uid", "samaccountname", "userprincipalname"),
        )
        realm = _realm_from_dn(bind_dn)
        if not (username or realm):
            return
        ident = state.host_identities.get(client_ip)
        if ident is None:
            ident = HostIdentity(ip=client_ip)
            state.host_identities[client_ip] = ident
        if username and ident.username is None:
            ident.username = username
        if realm and (ident.realm is None or (
            "." in realm and "." not in ident.realm
        )):
            ident.realm = realm
