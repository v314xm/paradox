"""Минимальный разбор LDAP из склеенного TCP-потока.

LDAPMessage — BER SEQUENCE: messageID, protocolOp (APPLICATION n),
опциональные controls. Сообщения идут подряд без внешней рамки, поэтому
читаем их через общий ``der.read_tlv`` до конца потока.

Что извлекаем для триажа AD:
  - bind: DN и код результата (без пароля — сохраняем только факт);
  - search: base DN, область, текстовый фильтр и список атрибутов;
  - result entry/done: DN объекта и код результата.

Фильтр рендерится в привычный вид ``(&(objectClass=user)(...))``:
по нему видно перечисление пользователей, запрос SPN (Kerberoasting)
и выборку memberOf (ADRecon).

Не разбираем LDAPS (636 — шифр) и BER indefinite-length (LDAP его
не использует).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from paradox.der import DerError, read_tlv

TAG_ENUMERATED = 0x0A
TAG_OCTET_STRING = 0x04
TAG_SEQUENCE = 0x30

LDAP_OPERATIONS: dict[int, str] = {
    0x42: "unbind_request",
    0x50: "abandon_request",
    0x60: "bind_request",
    0x61: "bind_response",
    0x63: "search_request",
    0x64: "search_result_entry",
    0x65: "search_result_done",
    0x66: "modify_request",
    0x67: "modify_response",
    0x68: "add_request",
    0x69: "add_response",
    0x6A: "delete_request",
    0x6B: "delete_response",
    0x6C: "modify_dn_request",
    0x6D: "modify_dn_response",
    0x6E: "compare_request",
    0x6F: "compare_response",
    0x77: "extended_request",
    0x78: "extended_response",
    0x79: "intermediate_response",
}

LDAP_SCOPES: dict[int, str] = {
    0: "base",
    1: "one",
    2: "sub",
}


@dataclass
class LdapMessage:
    """Разобранное LDAP-сообщение."""
    kind: str
    message_id: int = 0
    bind_dn: str | None = None
    base_dn: str | None = None
    scope: str | None = None
    filter: str | None = None
    attributes: tuple[str, ...] = ()
    result_code: int | None = None
    diagnostic: str | None = None
    object_name: str | None = None


@dataclass
class _Node:
    tag: int
    value: bytes = b""
    children: list[_Node] = field(default_factory=list)


def _parse_node(data: bytes, pos: int = 0) -> tuple[_Node, int]:
    tag, _length, value, next_pos = read_tlv(data, pos)
    node = _Node(tag=tag, value=value)
    if tag & 0x20:
        inner = 0
        while inner < len(value):
            child, inner = _parse_node(value, inner)
            node.children.append(child)
    return node, next_pos


def _text(node: _Node) -> str:
    return node.value.decode("utf-8", errors="replace")


def _int(node: _Node) -> int:
    return int.from_bytes(node.value, "big", signed=False)


def _render_value(node: _Node) -> str:
    return _text(node).replace("\\", "\\\\").replace(")", "\\)")


def _render_substrings(node: _Node) -> str:
    if not node.children:
        return "(*=*)"
    attr = _text(node.children[0])
    parts: list[str] = []
    for child in node.children[1:]:
        value = _render_value(child)
        if child.tag == 0x80:
            parts.append(value)
        else:
            parts.append("*" + value)
    if node.children[-1].tag == 0x81:
        parts.append("*")
    return f"({attr}={''.join(parts)})"


def render_ldap_filter(node: _Node) -> str:
    """LDAP-фильтр → текст вида ``(&(objectClass=user)(cn=*))``."""
    tag = node.tag
    if tag == 0xA0:
        return "(&" + "".join(
            render_ldap_filter(c) for c in node.children
        ) + ")"
    if tag == 0xA1:
        return "(|" + "".join(
            render_ldap_filter(c) for c in node.children
        ) + ")"
    if tag == 0xA2 and node.children:
        return "(!" + render_ldap_filter(node.children[0]) + ")"
    if tag == 0xA4:
        return _render_substrings(node)
    if tag == 0x87:
        return f"({_text(node)}=*)"
    if tag in (0xA3, 0xA5, 0xA6, 0xA8) and len(node.children) >= 2:
        op = {0xA3: "=", 0xA5: ">=", 0xA6: "<=", 0xA8: "~="}[tag]
        attr = _text(node.children[0])
        value = _render_value(node.children[1])
        return f"({attr}{op}{value})"
    if tag == 0xA9:
        rule = _text(node.children[0]) if len(node.children) >= 1 else ""
        attr = _text(node.children[1]) if len(node.children) >= 2 else ""
        value = (
            _render_value(node.children[2])
            if len(node.children) >= 3 else ""
        )
        return f"({attr}:{rule}:={value})"
    return "(?)"


def _first_value(nodes: list[_Node], tag: int) -> _Node | None:
    for node in nodes:
        if node.tag == tag:
            return node
    return None


def parse_ldap_message(data: bytes) -> LdapMessage | None:
    """Разобрать одно LDAPMessage из начала data."""
    try:
        root, _next = _parse_node(data, 0)
    except (DerError, ValueError):
        return None
    if root.tag != TAG_SEQUENCE or len(root.children) < 2:
        return None

    message_id_node, operation = root.children[0], root.children[1]
    message_id = _int(message_id_node) if message_id_node.tag == 0x02 else 0
    kind = LDAP_OPERATIONS.get(operation.tag, f"op_0x{operation.tag:02X}")
    message = LdapMessage(kind=kind, message_id=message_id)
    fields = operation.children

    if kind == "bind_request":
        name = _first_value(fields, TAG_OCTET_STRING)
        if name is not None:
            message.bind_dn = _text(name)

    elif kind == "bind_response":
        code = _first_value(fields, TAG_ENUMERATED)
        if code is not None:
            message.result_code = _int(code)
        diagnostics = [
            node for node in fields if node.tag == TAG_OCTET_STRING
        ]
        if len(diagnostics) >= 2:
            message.diagnostic = _text(diagnostics[1]) or None

    elif kind == "search_request":
        base = _first_value(fields, TAG_OCTET_STRING)
        if base is not None:
            message.base_dn = _text(base)
        scope = _first_value(fields, TAG_ENUMERATED)
        if scope is not None:
            message.scope = LDAP_SCOPES.get(_int(scope), str(_int(scope)))
        if len(fields) >= 7:
            message.filter = render_ldap_filter(fields[6])
        if len(fields) >= 8 and fields[7].tag == TAG_SEQUENCE:
            message.attributes = tuple(
                _text(node) for node in fields[7].children
                if node.tag == TAG_OCTET_STRING
            )

    elif kind == "search_result_entry":
        name = _first_value(fields, TAG_OCTET_STRING)
        if name is not None:
            message.object_name = _text(name)

    elif kind == "search_result_done":
        code = _first_value(fields, TAG_ENUMERATED)
        if code is not None:
            message.result_code = _int(code)

    return message


def parse_ldap_messages(stream: bytes) -> tuple[list[LdapMessage], int]:
    """Разобрать поток LDAP: (сообщения, число ошибок разбора)."""
    messages: list[LdapMessage] = []
    errors = 0
    pos = 0
    while pos < len(stream):
        try:
            _tag, _length, _value, next_pos = read_tlv(stream, pos)
        except (DerError, ValueError):
            errors += 1
            break
        if next_pos <= pos:
            errors += 1
            break
        message = parse_ldap_message(stream[pos:next_pos])
        if message is None:
            errors += 1
        else:
            messages.append(message)
        pos = next_pos
    return messages, errors
