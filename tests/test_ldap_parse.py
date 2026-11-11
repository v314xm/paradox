"""Разбор LDAP: bind, search, фильтры и поток сообщений."""
from paradox.ldap_parse import parse_ldap_message, parse_ldap_messages


def _len(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return _tlv(0x02, raw)


def _enum(value: int) -> bytes:
    return _tlv(0x0A, bytes([value]))


def _octet(value: str) -> bytes:
    return _tlv(0x04, value.encode("utf-8"))


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _search_request(base: str, ldap_filter: bytes, attrs: tuple[str, ...]):
    return _seq(
        _int(2),
        _tlv(
            0x63,
            _octet(base)
            + _enum(2)
            + _enum(0)
            + _int(0)
            + _int(0)
            + _tlv(0x01, b"\x00")
            + ldap_filter
            + _seq(*[_octet(attr) for attr in attrs]),
        ),
    )


def test_bind_request():
    message = parse_ldap_message(
        _seq(
            _int(1),
            _tlv(
                0x60,
                _int(3)
                + _octet("cn=admin,dc=corp,dc=local")
                + _tlv(0x80, b"secret"),
            ),
        ),
    )

    assert message is not None
    assert message.kind == "bind_request"
    assert message.bind_dn == "cn=admin,dc=corp,dc=local"


def test_bind_response_result_and_diagnostic():
    message = parse_ldap_message(
        _seq(
            _int(1),
            _tlv(
                0x61,
                _enum(49)
                + _octet("")
                + _octet("80090308: LdapErr: DSID-0C0903A9"),
            ),
        ),
    )

    assert message is not None
    assert message.result_code == 49
    assert "LdapErr" in (message.diagnostic or "")


def test_search_request_present_filter():
    message = parse_ldap_message(
        _search_request(
            "dc=corp,dc=local",
            _tlv(0x87, b"servicePrincipalName"),
            ("servicePrincipalName", "sAMAccountName"),
        ),
    )

    assert message is not None
    assert message.kind == "search_request"
    assert message.base_dn == "dc=corp,dc=local"
    assert message.scope == "sub"
    assert message.filter == "(servicePrincipalName=*)"
    assert message.attributes == (
        "servicePrincipalName", "sAMAccountName",
    )


def test_search_request_and_filter():
    ldap_filter = _tlv(
        0xA0,
        _tlv(0x87, b"objectClass")
        + _tlv(0xA3, _octet("objectClass") + _octet("user")),
    )
    message = parse_ldap_message(
        _search_request("dc=corp,dc=local", ldap_filter, ("cn",)),
    )

    assert message is not None
    assert message.filter == "(&(objectClass=*)(objectClass=user))"


def test_search_request_substrings():
    ldap_filter = _tlv(
        0xA4,
        _octet("cn")
        + _tlv(0x80, b"adm")
        + _tlv(0x81, b"in")
        + _tlv(0x82, b"istrator"),
    )
    message = parse_ldap_message(
        _search_request("dc=corp,dc=local", ldap_filter, ()),
    )

    assert message is not None
    assert message.filter == "(cn=adm*in*istrator)"


def test_search_result_entry_and_done():
    entry = parse_ldap_message(
        _seq(
            _int(2),
            _tlv(0x64, _octet("cn=alice,dc=corp,dc=local")),
        ),
    )
    done = parse_ldap_message(
        _seq(_int(2), _tlv(0x65, _enum(0) + _octet("") + _octet(""))),
    )

    assert entry is not None and entry.object_name.startswith("cn=alice")
    assert done is not None and done.result_code == 0


def test_stream_with_two_messages():
    bind = _seq(
        _int(1),
        _tlv(0x60, _int(3) + _octet("") + _tlv(0x80, b"")),
    )
    done = _seq(_int(1), _tlv(0x61, _enum(0) + _octet("") + _octet("")))
    messages, errors = parse_ldap_messages(bind + done)

    assert errors == 0
    assert [m.kind for m in messages] == ["bind_request", "bind_response"]


def test_truncated_stream_counts_error():
    message = _search_request(
        "dc=corp,dc=local", _tlv(0x87, b"cn"), ("cn",),
    )

    messages, errors = parse_ldap_messages(message[:-2])

    assert messages == []
    assert errors == 1


def test_not_ldap_returns_none():
    assert parse_ldap_message(b"GET / HTTP/1.1\r\n\r\n") is None
