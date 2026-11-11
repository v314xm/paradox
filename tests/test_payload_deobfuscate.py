"""Деобфускация PHP/JS/PowerShell без исполнения кода."""
import base64
import zlib

from paradox.payload_deobfuscate import deobfuscate


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


def test_php_base64_and_deflate_chain():
    code = b"echo 'hello from shell';"
    encoded = base64.b64encode(_raw_deflate(code))
    body = (
        b"<?php eval(gzinflate(base64_decode('" + encoded + b"'))); ?>"
    )

    layers = deobfuscate(body)

    assert layers
    assert any(b"echo 'hello from shell'" in layer.data for layer in layers)


def test_powershell_encoded_command():
    code = "Write-Output 'hello from powershell'"
    encoded = base64.b64encode(code.encode("utf-16-le"))
    body = b"powershell.exe -NoP -EncodedCommand " + encoded

    layers = deobfuscate(body)

    assert any(b"Write-Output" in layer.data for layer in layers)
    assert layers[0].label == "PowerShell -EncodedCommand"


def test_js_from_char_code():
    body = b"eval(String.fromCharCode(104, 101, 108, 108, 111))"

    layers = deobfuscate(body)

    assert any(layer.data == b"hello" for layer in layers)


def test_plain_text_has_no_layers():
    assert deobfuscate(b"just a normal line of text") == []


def test_html_entities_and_rot13():
    entities = deobfuscate(b"&#104;&#101;&#108;&#108;&#111;")
    assert any(layer.data == b"hello" for layer in entities)

    rot = deobfuscate(b"<?php echo str_rot13('uryyb'); ?>")
    assert any(layer.data == b"hello" for layer in rot)
