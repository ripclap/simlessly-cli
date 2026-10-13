"""Where stored credentials live: the OS secret store and a credentials file.

  macOS    Keychain, through `security` (service "simlessly-cli", account = setting)
  Linux    Secret Service, through `secret-tool` (attributes: service simlessly-cli, setting <name>)
  any OS   an INI credentials file, mode 0600, with a [default] section

Rules:
  * Nothing here prints. Errors are StoreError with messages that never contain a value, not even a
    line of the credentials file (parser errors are replaced).
  * Secrets never go on a command line: `secret-tool store` and `security -i` read them from stdin.
  * Reading is best effort: a missing tool, non-zero exit or undecodable answer means "not stored
    there" and the lookup moves on. A Secret Service timeout or keyring failure does too, but raises
    OSStoreUnavailable first so the caller stops asking the keyring and reports why.
  * Writing and removing treat any failure other than "no such item" as an error.
"""

from __future__ import annotations

import configparser
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping

SERVICE = "simlessly-cli"
SECTION = "default"
FILE_ENV_VAR = "SIMLESSLY_CREDENTIALS_FILE"
TOOL_TIMEOUT = 5  # seconds per lookup; a locked keyring could wait on an unseen prompt
STORE_TIMEOUT = 60  # seconds for store / clear, which may wait for a person to unlock the keyring
KEYCHAIN_TIMEOUT = 15
STORES = ("auto", "keychain", "secret-service", "file")

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class StoreError(Exception):
    """A store could not be read or written. The message never contains a value."""


class OSStoreUnavailable(StoreError):
    """The OS secret store hung or failed (keyring locked, no D-Bus)."""


class NoHomeError(StoreError):
    """No home directory, so the credentials file location is unknown."""


# ------------------------------------------------------------------ platform

def is_macos() -> bool:
    return sys.platform == "darwin"


def is_windows() -> bool:
    return sys.platform in ("win32", "cygwin")


def has_secret_service_platform() -> bool:
    """Secret Service exists on Linux and BSD, not macOS or Windows."""
    return not is_macos() and not is_windows()


def os_store_name() -> str | None:
    """'keychain' on macOS, 'secret-service' on Linux and BSD, None on Windows."""
    if is_macos():
        return "keychain"
    if has_secret_service_platform():
        return "secret-service"
    return None


def _run(cmd: list[str], runner, *, timeout: float, input_text: str | None = None):
    """One subprocess call with a timeout; stdin is closed unless input is given."""
    run = runner or subprocess.run
    # UTF-8 explicitly: the locale encoding must not decide a secret's bytes.
    kwargs: dict = {"capture_output": True, "text": True, "encoding": "utf-8", "timeout": timeout}
    if input_text is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = input_text
    return run(cmd, **kwargs)


# ------------------------------------------------------------------ macOS Keychain

KEYCHAIN_NOT_FOUND = 44  # `security` exit status for errSecItemNotFound; any other non-zero exit is a failure


def keychain_lookup(account: str, runner=None) -> str | None:
    """`security find-generic-password` for one account, or None on any failure."""
    if not is_macos() or shutil.which("security") is None:
        return None
    cmd = ["security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"]
    try:
        done = _run(cmd, runner, timeout=KEYCHAIN_TIMEOUT)
    except (OSError, subprocess.SubprocessError, ValueError):  # ValueError: undecodable output
        return None
    if done.returncode != 0:
        return None
    return done.stdout.rstrip("\n") or None


def _security_quote(value: str) -> str:
    """Quote one argument for `security -i`."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def keychain_store(account: str, value: str, runner=None) -> None:
    """Add or update the item. The value goes through stdin of `security -i`, never argv.

    (`-w` alone prompts on /dev/tty and `-w <value>` shows the secret in the process list.) The item
    is read back to confirm the quoting; on a mismatch it is deleted so a mangled secret is not left.
    """
    if not is_macos():
        raise StoreError("the Keychain is only available on macOS")
    if shutil.which("security") is None:
        raise StoreError("the `security` command was not found")
    if not value.isascii():
        # `security -w` prints non-ASCII passwords as hex, so they cannot be verified
        raise StoreError("the Keychain store only takes ASCII values; use --store file for this one")
    line = ("add-generic-password -U -s {svc} -a {acct} -w {val}\n"
            .format(svc=_security_quote(SERVICE), acct=_security_quote(account), val=_security_quote(value)))
    try:
        done = _run(["security", "-i"], runner, timeout=KEYCHAIN_TIMEOUT, input_text=line)
    except (OSError, subprocess.SubprocessError) as err:
        raise StoreError(f"the Keychain write failed ({type(err).__name__})") from None
    except ValueError:
        raise StoreError("the Keychain write failed (the value could not be encoded)") from None
    if done.returncode != 0:
        raise StoreError(f"the Keychain write failed (security exited {done.returncode})")
    if keychain_lookup(account, runner) != value:
        try:
            keychain_delete(account, runner)
            cleanup = "; the item was removed again"
        except StoreError:
            cleanup = (f"; it could not be removed, delete it in Keychain Access or with "
                       f"`simlessly config unset {account} --store keychain`")
        raise StoreError("the Keychain item could not be read back exactly as stored" + cleanup +
                         f" (service {SERVICE}, account {account})")


def keychain_delete(account: str, runner=None) -> bool:
    """Delete the item. True if removed, False if absent; any other failure raises."""
    if not is_macos() or shutil.which("security") is None:
        raise StoreError("the Keychain is only available on macOS")
    cmd = ["security", "delete-generic-password", "-s", SERVICE, "-a", account]
    try:
        done = _run(cmd, runner, timeout=KEYCHAIN_TIMEOUT)
    except (OSError, subprocess.SubprocessError, ValueError) as err:
        raise StoreError(f"the Keychain delete failed ({type(err).__name__})") from None
    if done.returncode == 0:
        return True
    if done.returncode == KEYCHAIN_NOT_FOUND:
        return False
    raise StoreError(f"the Keychain delete failed (security exited {done.returncode}); "
                     "nothing was confirmed removed")


# ------------------------------------------------------------------ Linux Secret Service

TIMED_OUT_MESSAGE = "secret-service: timed out (keyring locked?)"
UNREACHABLE_MESSAGE = "secret-service: could not reach the keyring (D-Bus or keyring error)"
FILE_HINT = "or use --store file for a credentials file instead"


def _lookup_state(done) -> str:
    """'found', 'absent' or 'failed' for a `secret-tool lookup` result.

    A missing item exits 1 with nothing on stderr; D-Bus or keyring trouble exits non-zero with stderr text.
    """
    if done.returncode == 0:
        return "found"
    if done.returncode == 1 and not (done.stderr or "").strip():
        return "absent"
    return "failed"


def secret_service_lookup(account: str, runner=None) -> str | None:
    """`secret-tool lookup` for one account.

    None when the item is absent, the tool is missing or its answer is unusable. Raises
    OSStoreUnavailable on a timeout or keyring/D-Bus failure, so the caller skips the keyring for the
    remaining settings instead of waiting (and prompting) again.
    """
    if not has_secret_service_platform() or shutil.which("secret-tool") is None:
        return None
    cmd = ["secret-tool", "lookup", "service", SERVICE, "setting", account]
    try:
        done = _run(cmd, runner, timeout=TOOL_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise OSStoreUnavailable(TIMED_OUT_MESSAGE) from None  # locked keyring waiting for an unlock prompt
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    state = _lookup_state(done)
    if state == "failed":
        raise OSStoreUnavailable(UNREACHABLE_MESSAGE)
    if state == "absent":
        return None
    return done.stdout.rstrip("\n") or None


def secret_service_available(runner=None) -> bool:
    """True when secret-tool exists and can reach a keyring (picks the `auto` store)."""
    if not has_secret_service_platform() or shutil.which("secret-tool") is None:
        return False
    cmd = ["secret-tool", "lookup", "service", SERVICE, "setting", "__availability-probe__"]
    try:
        done = _run(cmd, runner, timeout=TOOL_TIMEOUT)
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return _lookup_state(done) != "failed"


def _secret_tool(cmd: list[str], runner, *, timeout: float, input_text: str | None = None):
    """Run secret-tool for a write or delete; any failure is a StoreError without the value."""
    try:
        return _run(cmd, runner, timeout=timeout, input_text=input_text)
    except subprocess.TimeoutExpired:
        raise StoreError(f"secret-tool timed out (is the keyring locked? {FILE_HINT})") from None
    except (OSError, subprocess.SubprocessError) as err:
        raise StoreError(f"secret-tool failed ({type(err).__name__}); {FILE_HINT}") from None
    except ValueError:
        raise StoreError("secret-tool input or output could not be encoded as UTF-8") from None


def secret_service_store(account: str, value: str, runner=None) -> None:
    """`secret-tool store`, with the secret on stdin. Unlocking the keyring may need a person, so it gets STORE_TIMEOUT."""
    if not has_secret_service_platform():
        raise StoreError("Secret Service is not available on this platform")
    if shutil.which("secret-tool") is None:
        raise StoreError("secret-tool was not found (Debian/Ubuntu: apt install libsecret-tools)")
    cmd = ["secret-tool", "store", f"--label={SERVICE} {account}", "service", SERVICE, "setting", account]
    done = _secret_tool(cmd, runner, timeout=STORE_TIMEOUT, input_text=value)
    if done.returncode != 0:
        raise StoreError(f"secret-tool failed (exit {done.returncode}); is a keyring running and unlocked? "
                         f"{FILE_HINT}")


def secret_service_delete(account: str, runner=None) -> bool:
    """Remove the item. True if removed, False if absent; anything else raises.

    `secret-tool clear` cannot say whether anything matched and some versions report keyring trouble as
    success, so look first, clear, then look again.
    """
    if not has_secret_service_platform() or shutil.which("secret-tool") is None:
        raise StoreError("secret-tool was not found")
    lookup = ["secret-tool", "lookup", "service", SERVICE, "setting", account]
    state = _lookup_state(_secret_tool(lookup, runner, timeout=STORE_TIMEOUT))
    if state == "failed":
        raise StoreError("secret-tool could not read the keyring (locked, or no D-Bus session?); "
                         "nothing was confirmed removed")
    if state == "absent":
        return False
    cleared = _secret_tool(["secret-tool", "clear", "service", SERVICE, "setting", account], runner,
                           timeout=STORE_TIMEOUT)
    if cleared.returncode != 0:
        raise StoreError(f"secret-tool could not remove it (exit {cleared.returncode}); it is still stored")
    if _lookup_state(_secret_tool(lookup, runner, timeout=STORE_TIMEOUT)) == "found":
        raise StoreError("secret-tool reported success but the item is still stored")
    return True


def os_store_lookup(account: str, runner=None) -> str | None:
    """The platform's secret store: Keychain on macOS, Secret Service on Linux, none on Windows.

    Raises OSStoreUnavailable (Secret Service only) on a keyring timeout or failure.
    """
    if is_macos():
        return keychain_lookup(account, runner)
    if has_secret_service_platform():
        return secret_service_lookup(account, runner)
    return None


# ------------------------------------------------------------------ credentials file

def credentials_path(env: Mapping[str, str]) -> Path:
    """$SIMLESSLY_CREDENTIALS_FILE, else $XDG_CONFIG_HOME/simlessly-cli/credentials, else ~/.config/...

    Raises NoHomeError when a home directory is needed and there is none (e.g. an arbitrary uid in a container).
    """
    try:
        explicit = (env.get(FILE_ENV_VAR) or "").strip()
        if explicit:
            return Path(explicit).expanduser()
        xdg = (env.get("XDG_CONFIG_HOME") or "").strip()
        if xdg and os.path.isabs(xdg):  # XDG: ignore relative values
            return Path(xdg) / SERVICE / "credentials"
        return Path.home() / ".config" / SERVICE / "credentials"
    except RuntimeError:
        raise NoHomeError(f"no home directory, so there is no default credentials file location; "
                          f"set {FILE_ENV_VAR}") from None


def _posix_checks_apply() -> bool:
    return not is_windows() and hasattr(os, "getuid")


def _check_stat(path: Path, st) -> None:
    """Refuse a credentials file that others can read or someone else owns (as ssh does)."""
    if not _posix_checks_apply():
        return
    if st.st_uid != os.getuid():
        raise StoreError(f"credentials file {path} is not owned by you; refusing to use it "
                         f"(fix the owner, then run: chmod 600 {path})")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise StoreError(f"credentials file {path} is accessible by other users "
                         f"(mode {stat.S_IMODE(st.st_mode):04o}); refusing to use it. Run: chmod 600 {path}")


def check_file_permissions(path: Path) -> None:
    if _posix_checks_apply():
        _check_stat(path, os.stat(path))


def _real_path(path: Path) -> str:
    """The path to open; a symlinked file is followed once, here."""
    return os.path.realpath(path) if os.path.islink(path) else str(path)


def _unparseable(path: Path) -> StoreError:
    return StoreError(f"credentials file {path} could not be parsed; expected an INI file with a "
                      f"[{SECTION}] section (contents are not shown)")


def read_file_text(path: Path) -> str | None:
    """The file's text, or None when there is no regular file. Raises StoreError if it is unsafe.

    Opened once, and the owner/mode check runs on that descriptor, so the file checked is the file read.
    """
    real = _real_path(path)
    try:
        if not os.path.isfile(real):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(real, flags)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                return None
            _check_stat(path, st)
            return handle.read()
    except FileNotFoundError:
        return None
    except UnicodeDecodeError:
        raise _unparseable(path) from None
    except OSError as err:
        raise StoreError(f"credentials file {path} could not be read ({type(err).__name__})") from None


def _parse(text: str, path: Path) -> configparser.RawConfigParser:
    """Parse INI text. Parser errors become a generic one, since they quote lines."""
    parser = configparser.RawConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        raise _unparseable(path) from None
    return parser


def _default_values(parser: configparser.RawConfigParser) -> dict[str, str]:
    if not parser.has_section(SECTION):
        return {}
    return {k: v.strip() for k, v in parser.items(SECTION) if v.strip()}


def load_file(path: Path) -> dict[str, str]:
    """Settings in the file, or {} if absent. Raises StoreError if unsafe or unreadable."""
    text = read_file_text(path)
    return {} if text is None else _default_values(_parse(text, path))


class CredentialsFile:
    """Lazy reader of the credentials file. A refused file raises StoreError on every lookup.

    `for_env(env)` resolves the path only when first needed, so an environment-only setup needs no home directory.
    """

    def __init__(self, path: Path | None = None, env: Mapping[str, str] | None = None) -> None:
        self._path = path
        self._env = env if env is not None else {}
        self._values: dict[str, str] | None = None
        self._error: StoreError | None = None

    @classmethod
    def for_env(cls, env: Mapping[str, str]) -> "CredentialsFile":
        return cls(None, env)

    def fresh(self) -> "CredentialsFile":
        """The same file, uncached."""
        return CredentialsFile(self._path, self._env)

    @property
    def path(self) -> Path:
        """Raises NoHomeError when there is no home directory."""
        if self._path is None:
            self._path = credentials_path(self._env)
        return self._path

    def get(self, name: str) -> str | None:
        if self._values is None and self._error is None:
            try:
                self._values = load_file(self.path)
            except StoreError as err:
                self._error = err
        if self._error is not None:
            raise self._error
        return (self._values or {}).get(name)


# --- editing in place: comments, other sections and blank-valued keys survive a set / unset

_SECTION_RE = re.compile(r"^\[(.+)\]$")
_KEY_RE = re.compile(r"^([^=:]+?)\s*[=:]")


def _is_comment(stripped: str) -> bool:
    return stripped.startswith(("#", ";"))


def _edit_default(text: str, key: str, value: str | None) -> str:
    """Set (or, with value None, remove) one key of [default], touching only that line."""
    lines = text.splitlines(keepends=True)
    in_default, header_idx, last_idx = False, None, None
    key_start = key_end = None
    current_key = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue
        if line[0] not in " \t":
            m = _SECTION_RE.match(stripped)
            if m:
                in_default = m.group(1) == SECTION
                current_key = None
                if in_default and header_idx is None:
                    header_idx = last_idx = i
                continue
        if not in_default:
            continue
        last_idx = i
        if line[0] in " \t" and current_key is not None:  # continuation of a multi-line value
            if current_key == key and key_end == i:
                key_end = i + 1
            continue
        m = _KEY_RE.match(stripped)
        current_key = m.group(1).strip().lower() if m else None
        if current_key == key and key_start is None:
            key_start, key_end = i, i + 1
    new_line = None if value is None else f"{key} = {value}\n"
    if key_start is not None:
        lines[key_start:key_end] = [] if new_line is None else [new_line]
        return "".join(lines)
    if new_line is None:
        return text
    if header_idx is not None:
        at = last_idx + 1
        if lines[last_idx] and not lines[last_idx].endswith("\n"):
            lines[last_idx] += "\n"
        lines.insert(at, new_line)
        return "".join(lines)
    out = text
    if out and not out.endswith("\n"):
        out += "\n"
    if out.strip():
        out += "\n"
    return out + f"[{SECTION}]\n" + new_line


def _snapshot(parser: configparser.RawConfigParser) -> dict[str, dict[str, str]]:
    return {s: dict(parser.items(s)) for s in parser.sections()}


def _update_file(path: Path, key: str, value: str | None) -> bool:
    """Apply one set or unset. Returns True if the text changed. Refuses an unsafe file."""
    text = read_file_text(path)  # refuses an unsafe file instead of replacing it
    old = _parse(text or "", path)
    new_text = _edit_default(text or "", key, value)
    if new_text == (text or ""):
        return False  # nothing to change
    expected = _snapshot(old)
    if value is None:
        expected.get(SECTION, {}).pop(key, None)
    else:
        expected.setdefault(SECTION, {})[key] = value
    # Parse the edit back; write nothing unless it is exactly the one change.
    try:
        actual = _snapshot(_parse(new_text, path))
    except StoreError:
        actual = None
    if actual != expected:
        raise StoreError(f"credentials file {path} has a layout this tool cannot edit safely; "
                         f"nothing was written. Edit it by hand")
    _write_text(Path(_real_path(path)), new_text)
    return True


def _write_text(path: Path, text: str) -> None:
    """Atomic write: temp file in the same directory (0600), fsync, replace."""
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as err:
        raise StoreError(f"could not create {parent} ({type(err).__name__})") from None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".credentials-", dir=str(parent))
    except OSError as err:
        raise StoreError(f"could not write {path} ({type(err).__name__})") from None
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            if _posix_checks_apply():
                os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError as err:
        raise StoreError(f"could not write {path} ({type(err).__name__})") from None
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def file_store(path: Path, account: str, value: str) -> None:
    _update_file(path, account, value)


def file_delete(path: Path, account: str) -> bool:
    return _update_file(path, account, None)


# ------------------------------------------------------------------ choosing and using a store

def clean_value(value: str | None, *, ascii_only: bool = False) -> str:
    """A value fit to store: non-empty, no control characters. Errors never echo it.

    ascii_only is for keys sent in HTTP headers, where a non-ASCII character can only be a typo.
    """
    value = (value or "").strip()
    if not value:
        raise StoreError("the value is empty")
    if _CONTROL_RE.search(value):
        raise StoreError("the value contains a control character (a stray line break or tab?)")
    if ascii_only and not value.isascii():
        raise StoreError("the value contains a non-ASCII character")
    return value


def resolve_store(choice: str, runner=None) -> str:
    """Turn --store into 'keychain', 'secret-service' or 'file'. `auto` never fails."""
    if choice == "auto":
        if is_macos():
            return "keychain"
        if secret_service_available(runner):
            return "secret-service"
        return "file"
    if choice == "keychain" and not is_macos():
        raise StoreError("--store keychain only works on macOS")
    if choice == "secret-service" and not has_secret_service_platform():
        raise StoreError("--store secret-service only works on Linux")
    return choice


class Backends:
    """What `config set` and `config unset` use. Tests replace `runner` and the path."""

    def __init__(self, env: Mapping[str, str], runner: Callable | None = None) -> None:
        self.env, self.runner = env, runner

    @property
    def file_path(self) -> Path:
        return credentials_path(self.env)

    def store(self, choice: str, account: str, value: str) -> str:
        which = resolve_store(choice, self.runner)
        if which == "keychain":
            keychain_store(account, value, self.runner)
        elif which == "secret-service":
            secret_service_store(account, value, self.runner)
        else:
            file_store(self.file_path, account, value)
        return which

    def delete(self, choice: str, account: str) -> tuple[str, bool]:
        which = resolve_store(choice, self.runner)
        if which == "keychain":
            return which, keychain_delete(account, self.runner)
        if which == "secret-service":
            return which, secret_service_delete(account, self.runner)
        return which, file_delete(self.file_path, account)
