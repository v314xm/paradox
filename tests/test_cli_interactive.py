"""Тесты интерактивного ввода пути в CLI."""
from pathlib import Path
from unittest.mock import patch

import pytest

from paradox.cli import _ask_pcap_path


def test_ask_pcap_path_valid_file(tmp_path):
    """Пользователь ввёл путь к существующему файлу — возвращаем."""
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    with patch("builtins.input", return_value=str(p)):
        result = _ask_pcap_path()

    assert result == p.expanduser()


def test_ask_pcap_path_strips_quotes(tmp_path):
    """Путь в кавычках — кавычки снимаются."""
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    with patch("builtins.input", return_value=f'"{p}"'):
        result = _ask_pcap_path()

    assert result == p.expanduser()


def test_ask_pcap_path_retry_on_missing(tmp_path, capsys):
    """Несуществующий путь → повторный ввод."""
    p = tmp_path / "real.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    # Два вызова: первый — несуществующий, второй — валидный
    with patch("builtins.input", side_effect=[str(tmp_path / "nope.pcap"), str(p)]):
        result = _ask_pcap_path()

    assert result == p.expanduser()
    out = capsys.readouterr().out
    assert "Не найдено" in out or "nope.pcap" in out


def test_ask_pcap_path_retry_on_empty(tmp_path, capsys):
    """Пустой ввод → повтор."""
    p = tmp_path / "real.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    with patch("builtins.input", side_effect=["", "   ", str(p)]):
        result = _ask_pcap_path()

    assert result == p.expanduser()
