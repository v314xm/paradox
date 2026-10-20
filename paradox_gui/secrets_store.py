"""Хранилище секретов.

Основной путь — системный keyring (Windows Credential Manager,
macOS Keychain, Secret Service на Linux). Fallback — in-memory
session + os.environ. В settings.json секреты НЕ пишутся никогда.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

SERVICE_NAME = "Paradox"

# name → os.environ
_KEY_ENV = {
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    "abusech_auth_key": "ABUSECH_AUTH_KEY",
    "otx_api_key": "OTX_API_KEY",
    "greynoise_api_key": "GREYNOISE_API_KEY",
    "urlscan_api_key": "URLSCAN_API_KEY",
}


def _import_keyring():
    try:
        import keyring as kr
    except Exception:
        return None
    try:
        from keyring.backends.fail import Keyring as FailKeyring
        if isinstance(kr.get_keyring(), FailKeyring):
            return None
    except Exception:
        pass
    return kr


def detect_keyring() -> tuple[bool, str]:
    kr = _import_keyring()
    if kr is None:
        return False, "unavailable"
    try:
        return True, type(kr.get_keyring()).__name__
    except Exception:
        return False, "unavailable"


@dataclass
class SecretsStatus:
    keyring_available: bool
    keyring_backend: str
    loaded: tuple[str, ...]
    from_env: tuple[str, ...]
    unsaved_session: tuple[str, ...]


class SecretsStore:
    def __init__(self) -> None:
        self._kr = _import_keyring()
        self._session: dict[str, str] = {}

    def get(self, name: str) -> str:
        if self._kr is not None:
            try:
                v = self._kr.get_password(SERVICE_NAME, name)
                if v:
                    return v
            except Exception:
                pass
        if name in self._session:
            return self._session[name]
        env = _KEY_ENV.get(name)
        if env:
            return os.environ.get(env, "")
        return ""

    def set(self, name: str, value: str) -> bool:
        value = value.strip()
        if self._kr is None:
            if value:
                self._session[name] = value
            else:
                self._session.pop(name, None)
            self._apply_to_env(name, value)
            return False
        try:
            if value:
                self._kr.set_password(SERVICE_NAME, name, value)
            else:
                try:
                    self._kr.delete_password(SERVICE_NAME, name)
                except Exception:
                    pass
            self._apply_to_env(name, value)
            return True
        except Exception:
            if value:
                self._session[name] = value
            else:
                self._session.pop(name, None)
            self._apply_to_env(name, value)
            return False

    def delete(self, name: str) -> None:
        if self._kr is not None:
            try:
                self._kr.delete_password(SERVICE_NAME, name)
            except Exception:
                pass
        self._session.pop(name, None)
        env = _KEY_ENV.get(name)
        if env:
            os.environ.pop(env, None)

    def apply_all_to_env(self) -> None:
        for name in _KEY_ENV:
            v = self.get(name)
            if v:
                os.environ[_KEY_ENV[name]] = v

    def status(self) -> SecretsStatus:
        available, backend = detect_keyring()
        loaded: list[str] = []
        from_env: list[str] = []
        for name in _KEY_ENV:
            if self._kr is not None:
                try:
                    if self._kr.get_password(SERVICE_NAME, name):
                        loaded.append(name)
                        continue
                except Exception:
                    pass
            env = _KEY_ENV.get(name)
            if env and os.environ.get(env):
                from_env.append(name)
        return SecretsStatus(
            keyring_available=available,
            keyring_backend=backend,
            loaded=tuple(loaded),
            from_env=tuple(from_env),
            unsaved_session=tuple(sorted(self._session)),
        )

    @staticmethod
    def _apply_to_env(name: str, value: str) -> None:
        env = _KEY_ENV.get(name)
        if not env:
            return
        if value:
            os.environ[env] = value
        else:
            os.environ.pop(env, None)
