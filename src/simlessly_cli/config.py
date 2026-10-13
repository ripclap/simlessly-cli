"""Where settings come from, per setting: flag (base-url only), environment variable, OS secret
store (see store.py), credentials file (see README).

Values are held in memory only. Nothing here prints a value; `describe()` reports the source.
ENV_VARS maps each setting name (also the Keychain account / file key) to its environment variable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Mapping
from urllib.parse import urlsplit

from . import store
from .store import NoHomeError, OSStoreUnavailable, StoreError

KEYCHAIN_SERVICE = store.SERVICE
DEFAULT_BASE_URL = "https://rsp.simlessly.com"
VENDOR_HOST = "rsp.simlessly.com"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

ENV_VARS: dict[str, str] = {
    "access-key": "SIMLESSLY_ACCESS_KEY",
    "secret-key": "SIMLESSLY_SECRET_KEY",
    "config-name": "SIMLESSLY_CONFIG_NAME",
    "base-url": "SIMLESSLY_BASE_URL",
    "portal-token": "SIMLESSLY_PORTAL_TOKEN",
}
REQUIRED = ("access-key", "secret-key")
# Stored ASCII-only and scrubbed from output; a refused credentials file is an error for them.
# portal-token is not in REQUIRED, so `config check` does not demand it.
SECRET_SETTINGS = REQUIRED + ("portal-token",)
NO_KEYCHAIN_VAR = "SIMLESSLY_NO_KEYCHAIN"        # skip the OS secret store
NO_FILE_VAR = "SIMLESSLY_NO_CREDENTIALS_FILE"    # skip the credentials file

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

KeychainLookup = Callable[[str], "str | None"]  # setting name -> value or None


class ConfigError(Exception):
    """Settings are missing or unacceptable. The message never contains a secret value."""


@dataclass(frozen=True)
class Setting:
    name: str
    value: str | None = field(default=None, repr=False)  # never shown in repr
    source: str | None = None  # "flag" | "env" | "keychain" | "secret-service" | "file" | None
    detail: str | None = None  # for "file": the path

    @property
    def is_set(self) -> bool:
        return self.value is not None


def keychain_lookup(account: str, runner=None) -> str | None:
    """Read one value from the platform's secret store.

    Returns None on Windows, when the tool is missing, or when the item is not there. Raises
    store.OSStoreUnavailable when the Secret Service timed out or failed; Settings then stops asking it.
    """
    return store.os_store_lookup(account, runner)


class Settings:
    """Lazy resolver: stores are asked only when a setting is needed."""

    def __init__(
        self,
        env: Mapping[str, str],
        keychain: KeychainLookup | None = None,
        overrides: Mapping[str, str | None] | None = None,
        file_store: "store.CredentialsFile | None" = None,
        keychain_source: str = "keychain",
    ) -> None:
        self._env = env
        self._keychain = keychain
        self._file = file_store
        self._keychain_source = keychain_source
        self._overrides = {k: v for k, v in (overrides or {}).items() if v}
        self._cache: dict[str, Setting] = {}
        self._os_problem: str | None = None  # the OS store failed once; not asked again
        self._refused_optional: set[str] = set()  # optional settings skipped (file refused)
        self.warnings: list[str] = []  # non-fatal; shown on stderr

    def fresh(self) -> "Settings":
        """The same sources, uncached."""
        other = Settings(self._env, self._keychain, overrides=self._overrides,
                         file_store=self._file.fresh() if self._file is not None else None,
                         keychain_source=self._keychain_source)
        other._os_problem = self._os_problem  # do not wait on a hung keyring twice
        return other

    def _keychain_enabled(self) -> bool:
        return self._keychain is not None and not self._env.get(NO_KEYCHAIN_VAR) and self._os_problem is None

    def _file_enabled(self) -> bool:
        return self._file is not None and not self._env.get(NO_FILE_VAR)

    def file_path(self) -> str | None:
        """The credentials file location, or None when it is switched off or cannot be worked out."""
        if not self._file_enabled():
            return None
        try:
            return str(self._file.path)
        except StoreError:
            return None

    def os_store_problem(self) -> str | None:
        """Why the OS store was skipped after its first failure."""
        return self._os_problem

    def _lookup(self, name: str) -> Setting:
        if name in self._overrides:
            return Setting(name, self._overrides[name], "flag")
        env_value = (self._env.get(ENV_VARS[name]) or "").strip()
        if env_value:
            return Setting(name, env_value, "env")
        if self._keychain_enabled():
            try:
                kc_value = (self._keychain(name) or "").strip()
            except OSStoreUnavailable as err:
                self._os_problem, kc_value = str(err), ""
            if kc_value:
                return Setting(name, kc_value, self._keychain_source)
        if self._file_enabled():
            try:
                file_value = (self._file.get(name) or "").strip()
            except NoHomeError:
                file_value = ""  # no home directory, no default file
            except StoreError as err:
                if name in SECRET_SETTINGS:
                    raise ConfigError(str(err)) from None
                # An optional setting falls back to its default with a warning, so a bad file does not
                # break commands whose credentials come from elsewhere.
                self._refused_optional.add(name)
                if str(err) not in self.warnings:
                    self.warnings.append(str(err))
                file_value = ""
            if file_value:
                return Setting(name, file_value, "file", str(self._file.path))
        return Setting(name)

    def get(self, name: str) -> Setting:
        """The setting and its source. Raises ConfigError if the credentials file is refused."""
        if name not in self._cache:
            self._cache[name] = self._lookup(name)
        return self._cache[name]

    def env_value(self, var: str) -> str | None:
        """A raw environment variable (for the SIM secrets, which are not stored settings)."""
        return (self._env.get(var) or "").strip() or None

    def require(self, name: str) -> str:
        setting = self.get(name)
        if setting.value is None:
            raise ConfigError(
                f"{name} is not set. Set {ENV_VARS[name]}, or run `simlessly config set {name}`. "
                "Run `simlessly config check` to see what is set and from where."
            )
        if _CONTROL_RE.search(setting.value):
            # The value is not echoed. Header values cannot hold line breaks.
            raise ConfigError(
                f"{name} contains a control character (a stray line break or tab?) from the "
                f"{setting.source}. Re-enter it without extra characters."
            )
        return setting.value

    def base_url(self) -> str:
        raw = self.get("base-url").value
        return validate_base_url(raw) if raw else DEFAULT_BASE_URL

    def secrets(self) -> list[str]:
        """Known credential values, for scrubbing output."""
        return [s.value for n in ("access-key", "secret-key") if (s := self._cache.get(n)) and s.value]

    def describe(self) -> list[tuple[str, str]]:
        """(name, 'set (<source>)' or 'missing') per setting. No values."""
        rows = []
        for name in ENV_VARS:
            try:
                s = self.get(name)
            except ConfigError:
                rows.append((name, "missing (credentials file refused)" if name in REQUIRED
                             else "missing (optional; credentials file refused)"))
                continue
            if s.is_set:
                where = f"file {s.detail}" if s.source == "file" else s.source
                rows.append((name, f"set ({where})"))
            elif name in REQUIRED:
                rows.append((name, "missing"))
            elif name == "base-url":
                refused = "; credentials file refused" if name in self._refused_optional else ""
                rows.append((name, f"not set (default {DEFAULT_BASE_URL}{refused})"))
            else:
                refused = "; credentials file refused" if name in self._refused_optional else ""
                rows.append((name, f"missing (optional{refused})"))
        return rows

    def file_problem(self) -> str | None:
        """Why the credentials file is refused, else None."""
        if not self._file_enabled():
            return None
        try:
            self._file.get("access-key")
        except NoHomeError:
            return None
        except StoreError as err:
            return str(err)
        return None


def validate_base_url(raw: str) -> str:
    """Accept only the vendor origin or a loopback http URL (for tests).

    The signature does not cover the URL, so pinning the destination keeps a signed request from being replayed elsewhere.
    """
    raw = raw.strip()
    if "?" in raw or "#" in raw:
        raise ConfigError("base URL must not contain a query or fragment")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ConfigError("base URL is not a valid URL") from None
    host = (parts.hostname or "").lower()
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ConfigError("base URL must not contain credentials")
    if parts.scheme == "https" and host == VENDOR_HOST and port is None and parts.path in ("", "/"):
        return DEFAULT_BASE_URL
    if parts.scheme == "http" and host in LOOPBACK_HOSTS:
        return raw.rstrip("/")
    raise ConfigError(
        f"base URL refused: only {DEFAULT_BASE_URL} or an http loopback address "
        "(127.0.0.1 / localhost / [::1]) is allowed"
    )
