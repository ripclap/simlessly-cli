"""Credential sources and `config set/unset`, with platforms simulated.

The real `security` and `secret-tool` never run (support.py makes that an error): sys.platform,
shutil.which and subprocess.run are patched, and HOME is a temp dir.
"""

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import support
from support import ACCESS, SECRET, CliTestCase, ok
from simlessly_cli import cli, config, store
from simlessly_cli.config import ConfigError, Settings

POSIX = os.name == "posix"
VALUE = "STORED-VALUE-must-never-print-777"


class TTY(io.StringIO):
    def isatty(self):
        return True


class Runner:
    """A fake subprocess.run. `handler(cmd, kwargs)` returns (returncode, stdout, stderr) or raises."""

    def __init__(self, handler=None):
        self.handler = handler or (lambda cmd, kw: (1, "", ""))
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        result = self.handler(list(cmd), kw)
        return subprocess.CompletedProcess(cmd, result[0], stdout=result[1], stderr=result[2])


@contextlib.contextmanager
def fake_platform(name, runner=None, tools=("secret-tool",)):
    runner = runner or Runner()
    which = lambda cmd, *a, **k: f"/usr/bin/{cmd}" if cmd in tools else None
    with mock.patch.object(sys, "platform", name), mock.patch.object(shutil, "which", which), \
            mock.patch.object(subprocess, "run", runner):
        yield runner


def write_cred_file(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if POSIX:
        os.chmod(path, mode)
    return path


class TmpMixin:
    def make_tmp(self):
        tmp = Path(tempfile.mkdtemp(prefix="simlessly-store-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        return tmp


# ------------------------------------------------------------------ source order

class SourceOrderTests(unittest.TestCase, TmpMixin):
    def test_env_then_os_store_then_file(self):
        tmp = self.make_tmp()
        f = store.CredentialsFile(write_cred_file(tmp / "creds", "[default]\naccess-key = file-a\nsecret-key = file-s\nconfig-name = file-c\n"))
        asked = []
        kc = lambda name: asked.append(name) or {"secret-key": "os-s", "config-name": "os-c"}.get(name)
        s = Settings({"SIMLESSLY_CONFIG_NAME": "env-c"}, kc, file_store=f, keychain_source="secret-service")
        self.assertEqual((s.get("config-name").value, s.get("config-name").source), ("env-c", "env"))
        self.assertEqual((s.get("secret-key").value, s.get("secret-key").source), ("os-s", "secret-service"))
        a = s.get("access-key")
        self.assertEqual((a.value, a.source, a.detail), ("file-a", "file", str(tmp / "creds")))
        self.assertNotIn("config-name", asked)  # env wins: the OS store is not even asked

    def test_flag_beats_everything(self):
        f = types.SimpleNamespace(path=Path("/nope"), get=lambda n: "file")
        s = Settings({"SIMLESSLY_BASE_URL": "http://127.0.0.1:1"}, lambda n: "os", {"base-url": "http://localhost:2"}, file_store=f)
        self.assertEqual(s.get("base-url").source, "flag")

    def test_switches_skip_stores(self):
        f = types.SimpleNamespace(path=Path("/nope"), get=lambda n: "file")
        self.assertFalse(Settings({"SIMLESSLY_NO_KEYCHAIN": "1", "SIMLESSLY_NO_CREDENTIALS_FILE": "1"}, lambda n: "os", file_store=f).get("access-key").is_set)
        self.assertEqual(Settings({"SIMLESSLY_NO_KEYCHAIN": "1"}, lambda n: "os", file_store=f).get("access-key").source, "file")
        self.assertEqual(Settings({"SIMLESSLY_NO_CREDENTIALS_FILE": "1"}, lambda n: "os", file_store=f).get("access-key").source, "keychain")

    def test_refused_file_raises_only_when_needed(self):
        tmp = self.make_tmp()
        bad = store.CredentialsFile(write_cred_file(tmp / "creds", f"[default]\naccess-key = {VALUE}\n", 0o644))
        # env has the value: the file is never read
        self.assertEqual(Settings({"SIMLESSLY_ACCESS_KEY": "e"}, None, file_store=bad).get("access-key").source, "env")
        if POSIX:
            with self.assertRaises(ConfigError) as cm:
                Settings({}, None, file_store=bad).require("access-key")
            self.assertIn("chmod 600", str(cm.exception))
            self.assertNotIn(VALUE, str(cm.exception))


class LinuxFlowTests(CliTestCase, TmpMixin):
    """Through main(): secret-tool first, then the file; every failure falls through silently."""

    def setUp(self):
        super().setUp()
        self.tmp = self.make_tmp()
        self.path = self.tmp / "creds"
        self.env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path), "SIMLESSLY_BASE_URL": self.server.url}

    def run_linux(self, handler, *argv, tools=("secret-tool",), env=None):
        with fake_platform("linux", Runner(handler), tools) as runner:
            result = self.run_cli(*argv, env=env or self.env, keychain=config.keychain_lookup)
        return result, runner

    def test_secret_tool_then_file_labels(self):
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n")
        handler = lambda cmd, kw: (0, SECRET + "\n", "") if cmd[-1] == "secret-key" else (1, "", "")
        (code, out, err), runner = self.run_linux(handler, "config", "check")
        self.assertEqual(code, 0, out + err)
        self.assertIn("set (secret-service)", out)
        self.assertIn(f"set (file {self.path})", out)
        self.assertNoSecrets(out, err)
        self.assertEqual(self.server.requests, [])
        self.assertEqual(runner.calls[0][0], ["secret-tool", "lookup", "service", "simlessly-cli", "setting", "access-key"])

    def test_lookup_uses_short_timeout_and_closed_stdin(self):
        _, runner = self.run_linux(lambda c, k: (1, "", ""), "config", "check")
        for _, kw in runner.calls:
            self.assertLessEqual(kw["timeout"], 5)
            self.assertEqual(kw["stdin"], subprocess.DEVNULL)

    def test_every_failure_falls_through_to_the_file_silently(self):
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n")

        def timeout(cmd, kw):
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        def oserror(cmd, kw):
            raise OSError("no such thing")

        cases = {
            "locked/no keyring (exit 1, error text)": (lambda c, k: (1, "", "Cannot autolaunch D-Bus without X11")),
            "other non-zero exit": (lambda c, k: (2, "", "")),
            "timeout": timeout,
            "OSError": oserror,
            "empty output": (lambda c, k: (0, "\n", "")),
        }
        for label, handler in cases.items():
            (code, out, err), _ = self.run_linux(handler, "config", "check")
            self.assertEqual(code, 0, label)
            self.assertEqual(err, "", label)
            self.assertNotIn("secret-service", out.split("Lookup order")[0], label)
            self.assertEqual(out.count(f"set (file {self.path})"), 2, label)

    def test_secret_tool_missing_does_not_even_try(self):
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n")
        (code, out, err), runner = self.run_linux(lambda c, k: (0, "x", ""), "config", "check", tools=())
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(runner.calls, [])
        self.assertIn("secret-tool not found", out)

    def test_no_security_hint_on_linux_and_file_hint_shown(self):
        (code, out, _), _ = self.run_linux(lambda c, k: (1, "", ""), "config", "check", tools=())
        self.assertEqual(code, 1)
        self.assertNotIn("security", out)
        self.assertNotIn("Keychain", out)
        self.assertIn("--store file", out)
        self.assertIn(str(self.path), out)
        self.assertIn("SIMLESSLY_ACCESS_KEY", out)

    def test_hint_with_secret_tool_present(self):
        (_, out, _), _ = self.run_linux(lambda c, k: (1, "", ""), "config", "check")
        self.assertIn("--store secret-service", out)
        self.assertNotIn("security find", out)

    def test_env_wins_over_both_stores(self):
        write_cred_file(self.path, "[default]\naccess-key = file-a\nsecret-key = file-s\n")
        env = {**self.env, "SIMLESSLY_ACCESS_KEY": ACCESS, "SIMLESSLY_SECRET_KEY": SECRET}
        (code, out, _), runner = self.run_linux(lambda c, k: (0, "os\n", ""), "config", "check", env=env)
        self.assertEqual(code, 0)
        self.assertEqual(out.count("set (env)"), 3)  # access-key, secret-key, base-url
        self.assertFalse([c for c, _ in runner.calls if c[-1] in ("access-key", "secret-key")])

    def test_credentials_from_file_drive_a_signed_call(self):
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n")
        self.server.routes["/api/v1/config/list"] = lambda r: ok({"configs": ["a"]})
        (code, out, err), _ = self.run_linux(lambda c, k: (1, "", ""), "configs", "list")
        self.assertEqual(code, 0, err)
        self.assertAllSigned()
        self.assertEqual(len(self.server.requests), 1)

    def test_refused_file_is_reported_by_check_and_by_commands(self):
        if not POSIX:
            self.skipTest("POSIX permissions")
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n", 0o644)
        (code, out, err), _ = self.run_linux(lambda c, k: (1, "", ""), "config", "check")
        self.assertEqual(code, 1)
        self.assertIn("credentials file problem", out)
        self.assertIn("chmod 600", out)
        self.assertIn("credentials file refused", out)
        self.assertNoSecrets(out, err)
        (code, out, err), _ = self.run_linux(lambda c, k: (1, "", ""), "configs", "list")
        self.assertEqual(code, 1)
        self.assertIn(str(self.path), err)
        self.assertNoSecrets(out, err)
        self.assertEqual(self.server.requests, [])
        (code, out, err), _ = self.run_linux(lambda c, k: (1, "", ""), "config", "check", "--json")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["credentials_file"], str(self.path))
        self.assertIn("chmod 600", data["credentials_file_error"])


class MacosAndWindowsCheckTests(CliTestCase, TmpMixin):
    def setUp(self):
        super().setUp()
        self.path = self.make_tmp() / "creds"
        self.env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path)}

    def test_macos_uses_security_unchanged(self):
        handler = lambda cmd, kw: (0, ACCESS + "\n", "") if (cmd[:2] == ["security", "find-generic-password"] and cmd[5] in ("access-key", "secret-key")) else (1, "", "")
        with fake_platform("darwin", Runner(handler), tools=("security",)) as runner:
            code, out, err = self.run_cli("config", "check", env=self.env, keychain=config.keychain_lookup)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(out.count("set (keychain)"), 2)
        self.assertIn("Keychain", out)
        self.assertEqual(runner.calls[0][0], ["security", "find-generic-password", "-s", "simlessly-cli", "-a", "access-key", "-w"])
        self.assertNotIn("secret-tool", out)

    def test_windows_env_and_file_only(self):
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n", 0o666)
        with fake_platform("win32", Runner(lambda c, k: self.fail("no subprocess on Windows")), tools=("security", "secret-tool")), \
                mock.patch.object(os, "getuid", side_effect=AssertionError("getuid on Windows"), create=True):
            code, out, err = self.run_cli("config", "check", env=self.env, keychain=config.keychain_lookup)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(out.count(f"set (file {self.path})"), 2)
        self.assertNotIn("security", out)
        self.assertNotIn("secret-tool", out)
        self.assertNotIn("Keychain", out)

    def test_windows_lookup_is_none(self):
        with fake_platform("win32", Runner(lambda c, k: self.fail("no subprocess")), tools=("security", "secret-tool")):
            self.assertIsNone(config.keychain_lookup("access-key"))
            self.assertIsNone(store.os_store_name())


# ------------------------------------------------------------------ the credentials file

class CredentialsFileTests(unittest.TestCase, TmpMixin):
    def test_path_resolution(self):
        home = Path.home()
        self.assertEqual(store.credentials_path({}), home / ".config" / "simlessly-cli" / "credentials")
        if POSIX:
            self.assertEqual(store.credentials_path({"XDG_CONFIG_HOME": "/xdg"}), Path("/xdg/simlessly-cli/credentials"))
        self.assertEqual(store.credentials_path({"XDG_CONFIG_HOME": "relative/dir"}), home / ".config" / "simlessly-cli" / "credentials")
        self.assertEqual(store.credentials_path({"XDG_CONFIG_HOME": ""}), home / ".config" / "simlessly-cli" / "credentials")
        override = {"SIMLESSLY_CREDENTIALS_FILE": "/elsewhere/creds", "XDG_CONFIG_HOME": "/xdg"}
        self.assertEqual(store.credentials_path(override), Path("/elsewhere/creds"))

    def test_permission_modes(self):
        if not POSIX:
            self.skipTest("POSIX permissions")
        tmp = self.make_tmp()
        for mode, allowed in ((0o600, True), (0o400, True), (0o644, False), (0o640, False), (0o660, False), (0o604, False), (0o700, True)):
            path = write_cred_file(tmp / f"c{mode:o}", f"[default]\naccess-key = {VALUE}\n", mode)
            if allowed:
                self.assertEqual(store.load_file(path), {"access-key": VALUE}, oct(mode))
            else:
                with self.assertRaises(store.StoreError) as cm:
                    store.load_file(path)
                msg = str(cm.exception)
                self.assertIn(str(path), msg)
                self.assertIn(f"chmod 600 {path}", msg)
                self.assertNotIn(VALUE, msg)

    def test_wrong_owner_is_refused(self):
        if not POSIX:
            self.skipTest("POSIX ownership")
        path = write_cred_file(self.make_tmp() / "creds", f"[default]\naccess-key = {VALUE}\n")
        other = types.SimpleNamespace(st_uid=os.getuid() + 1, st_mode=stat.S_IFREG | 0o600)
        with mock.patch.object(os, "fstat", return_value=other):
            with self.assertRaises(store.StoreError) as cm:
                store.load_file(path)
        self.assertIn("not owned by you", str(cm.exception))
        self.assertIn(str(path), str(cm.exception))
        self.assertNotIn(VALUE, str(cm.exception))

    def test_windows_skips_posix_checks(self):
        path = write_cred_file(self.make_tmp() / "creds", f"[default]\naccess-key = {VALUE}\n", 0o666 if POSIX else 0o600)
        with mock.patch.object(sys, "platform", "win32"), mock.patch.object(os, "getuid", side_effect=AssertionError, create=True):
            self.assertEqual(store.load_file(path), {"access-key": VALUE})

    def test_missing_file_is_empty_and_directory_is_not_a_file(self):
        tmp = self.make_tmp()
        self.assertEqual(store.load_file(tmp / "absent"), {})
        self.assertEqual(store.load_file(tmp), {})

    def test_unparseable_file_error_never_quotes_it(self):
        tmp = self.make_tmp()
        for text in (f"{VALUE}\n", f"[default]\nnot a pair {VALUE}\n", f"[default]\naccess-key = {VALUE}\naccess-key = {VALUE}\n"):
            path = write_cred_file(tmp / "bad", text)
            with self.assertRaises(store.StoreError) as cm:
                store.load_file(path)
            self.assertNotIn(VALUE, str(cm.exception))
            self.assertIn(str(path), str(cm.exception))
        path = tmp / "binary"
        path.write_bytes(b"[default]\naccess-key = \xff\xfe\n")
        if POSIX:
            os.chmod(path, 0o600)
        with self.assertRaises(store.StoreError):
            store.load_file(path)

    def test_percent_and_equals_survive(self):
        tmp = self.make_tmp()
        path = tmp / "creds"
        tricky = "a%b=c;d#e%(x)s"
        store.file_store(path, "secret-key", tricky)
        self.assertEqual(store.load_file(path), {"secret-key": tricky})


# ------------------------------------------------------------------ config set / unset

class ConfigSetTests(CliTestCase, TmpMixin):
    def setUp(self):
        super().setUp()
        self.tmp = self.make_tmp()
        self.path = self.tmp / "conf" / "simlessly-cli" / "credentials"
        self.env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path), "SIMLESSLY_NO_KEYCHAIN": "1"}

    def set_prompted(self, *argv, value=VALUE, runner=None, platform=None, tools=("secret-tool",), env=None):
        """Run `config set` on a fake TTY whose hidden prompt returns `value`."""
        prompts = []
        getpass = lambda prompt="", stream=None: prompts.append(prompt) or value
        ctx = fake_platform(platform, runner, tools) if platform else contextlib.nullcontext()
        with ctx, mock.patch.object(cli.getpass, "getpass", getpass):
            result = self.run_cli("config", "set", *argv, env=env or self.env, stdin=TTY(""))
        return result, prompts

    # ---- file store
    def test_file_store_prompt_message_modes_and_content(self):
        (code, out, err), prompts = self.set_prompted("secret-key", "--store", "file")
        self.assertEqual((code, out, err), (0, "stored secret-key in file\n", ""))
        self.assertEqual(len(prompts), 1)
        self.assertNotIn(VALUE, prompts[0])
        self.assertEqual(store.load_file(self.path), {"secret-key": VALUE})
        if POSIX:
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["credentials"])  # no temp left behind

    def test_file_store_keeps_other_keys_and_replaces_same_key(self):
        self.set_prompted("access-key", "--store", "file", value="first")
        self.set_prompted("secret-key", "--store", "file", value="second")
        self.set_prompted("access-key", "--store", "file", value="third")
        self.assertEqual(store.load_file(self.path), {"access-key": "third", "secret-key": "second"})

    def test_file_write_is_atomic_temp_then_replace(self):
        self.set_prompted("access-key", "--store", "file", value="original")
        calls = []
        real_replace = os.replace
        spy = lambda src, dst: calls.append((Path(src), Path(dst))) or real_replace(src, dst)
        with mock.patch.object(os, "replace", spy):
            self.set_prompted("secret-key", "--store", "file", value="added")
        self.assertEqual(len(calls), 1)
        src, dst = calls[0]
        self.assertEqual(dst, self.path)
        self.assertEqual(src.parent, self.path.parent)
        self.assertNotEqual(src, dst)
        self.assertFalse(src.exists())

    def test_failed_replace_leaves_original_and_no_temp(self):
        self.set_prompted("access-key", "--store", "file", value="original")
        before = self.path.read_text()
        with mock.patch.object(os, "replace", side_effect=OSError("disk gone")):
            (code, out, err), _ = self.set_prompted("secret-key", "--store", "file")
        self.assertEqual(code, 1)
        self.assertIn("could not store secret-key", err)
        self.assertNoSecrets(out, err, extra=(VALUE,))
        self.assertEqual(self.path.read_text(), before)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["credentials"])

    def test_existing_unsafe_file_is_not_overwritten(self):
        if not POSIX:
            self.skipTest("POSIX permissions")
        write_cred_file(self.path, "[default]\naccess-key = keepme\n", 0o644)
        (code, out, err), _ = self.set_prompted("secret-key", "--store", "file")
        self.assertEqual(code, 1)
        self.assertIn("chmod 600", err)
        self.assertEqual(self.path.read_text(), "[default]\naccess-key = keepme\n")
        self.assertNotIn(VALUE, out + err)

    def test_existing_directory_mode_is_left_alone(self):
        if not POSIX:
            self.skipTest("POSIX permissions")
        self.path.parent.mkdir(parents=True, mode=0o755)
        os.chmod(self.path.parent, 0o755)
        self.set_prompted("access-key", "--store", "file")
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_set_then_use_end_to_end(self):
        self.server.routes["/api/v1/config/list"] = lambda r: ok({"configs": ["a"]})
        self.set_prompted("access-key", "--store", "file", value=ACCESS)
        self.set_prompted("secret-key", "--store", "file", value=SECRET)
        env = {**self.env, "SIMLESSLY_BASE_URL": self.server.url}
        code, out, err = self.run_cli("configs", "list", env=env)
        self.assertEqual(code, 0, err)
        self.assertAllSigned()

    # ---- keychain
    def keychain_handler(self, stored):
        def handler(cmd, kw):
            if cmd == ["security", "-i"]:
                stored["input"] = kw["input"]
                return (0, "", "")
            if cmd[:2] == ["security", "find-generic-password"]:
                return (0, VALUE + "\n", "") if stored.get("input") else (44, "", "")
            return (0, "", "")
        return handler

    def test_keychain_store_keeps_value_off_argv(self):
        stored = {}
        runner = Runner(self.keychain_handler(stored))
        (code, out, err), _ = self.set_prompted("access-key", "--store", "keychain", runner=runner, platform="darwin", tools=("security",))
        self.assertEqual((code, out, err), (0, "stored access-key in keychain\n", ""))
        self.assertEqual(runner.calls[0][0], ["security", "-i"])
        self.assertEqual(runner.calls[0][1]["input"], 'add-generic-password -U -s "simlessly-cli" -a "access-key" -w "%s"\n' % VALUE)
        for cmd, _ in runner.calls:
            self.assertNotIn(VALUE, " ".join(cmd))
        self.assertEqual(runner.calls[1][0], ["security", "find-generic-password", "-s", "simlessly-cli", "-a", "access-key", "-w"])
        self.assertFalse(self.path.exists())

    def test_keychain_quoting(self):
        self.assertEqual(store._security_quote('a"b\\c d'), '"a\\"b\\\\c d"')

    def test_keychain_readback_mismatch_fails_without_the_value(self):
        runner = Runner(lambda cmd, kw: (0, "something-else\n", "") if cmd[1] == "find-generic-password" else (0, "", ""))
        (code, out, err), _ = self.set_prompted("access-key", "--store", "keychain", runner=runner, platform="darwin", tools=("security",))
        self.assertEqual(code, 1)
        self.assertIn("read back", err)
        self.assertNotIn(VALUE, out + err)

    def test_keychain_failure_message(self):
        runner = Runner(lambda cmd, kw: (1, "", f"boom {VALUE}"))
        (code, out, err), _ = self.set_prompted("access-key", "--store", "keychain", runner=runner, platform="darwin", tools=("security",))
        self.assertEqual(code, 1)
        self.assertNotIn(VALUE, out + err)

    def test_keychain_refused_off_macos(self):
        (code, _, err), _ = self.set_prompted("access-key", "--store", "keychain", platform="linux", runner=Runner())
        self.assertEqual(code, 1)
        self.assertIn("only works on macOS", err)
        self.assertFalse(self.path.exists())

    # ---- secret service
    def test_secret_service_store_reads_value_from_stdin_not_argv(self):
        runner = Runner(lambda cmd, kw: (0, "", ""))
        (code, out, err), _ = self.set_prompted("secret-key", "--store", "secret-service", runner=runner, platform="linux")
        self.assertEqual((code, out, err), (0, "stored secret-key in secret-service\n", ""))
        (cmd, kw), = runner.calls
        self.assertEqual(cmd, ["secret-tool", "store", "--label=simlessly-cli secret-key", "service", "simlessly-cli", "setting", "secret-key"])
        self.assertEqual(kw["input"], VALUE)
        self.assertEqual(kw["timeout"], store.STORE_TIMEOUT)  # interactive: a person may have to unlock the keyring
        self.assertGreaterEqual(store.STORE_TIMEOUT, 60)
        self.assertNotIn(VALUE, " ".join(cmd))
        self.assertFalse(self.path.exists())

    def test_secret_service_failures_never_show_the_value(self):
        def timeout(cmd, kw):
            raise subprocess.TimeoutExpired(cmd, 5)
        for handler in (lambda c, k: (1, "", f"locked {VALUE}"), timeout, lambda c, k: (_ for _ in ()).throw(OSError(VALUE))):
            (code, out, err), _ = self.set_prompted("secret-key", "--store", "secret-service", runner=Runner(handler), platform="linux")
            self.assertEqual(code, 1)
            self.assertIn("could not store secret-key", err)
            self.assertNotIn(VALUE, out + err)

    def test_secret_service_without_tool(self):
        (code, _, err), _ = self.set_prompted("secret-key", "--store", "secret-service", runner=Runner(), platform="linux", tools=())
        self.assertEqual(code, 1)
        self.assertIn("secret-tool was not found", err)

    # ---- auto
    def test_auto_choices(self):
        ok_probe = Runner(lambda c, k: (1, "", ""))          # keyring answers: item not found
        no_bus = Runner(lambda c, k: (1, "", "Cannot autolaunch D-Bus"))
        cases = [
            ("darwin", Runner(self.keychain_handler({})), ("security",), "keychain"),
            ("linux", ok_probe, ("secret-tool",), "secret-service"),
            ("linux", no_bus, ("secret-tool",), "file"),
            ("linux", Runner(), (), "file"),
            ("win32", Runner(), ("security", "secret-tool"), "file"),
        ]
        for platform, runner, tools, expected in cases:
            with fake_platform(platform, runner, tools):
                self.assertEqual(store.resolve_store("auto", runner), expected, platform)

    def test_auto_on_linux_with_working_keyring_stores_there(self):
        runner = Runner(lambda cmd, kw: (1, "", "") if cmd[1] == "lookup" else (0, "", ""))
        (code, out, _), _ = self.set_prompted("access-key", runner=runner, platform="linux")
        self.assertEqual((code, out), (0, "stored access-key in secret-service\n"))
        self.assertFalse(self.path.exists())

    def test_auto_on_headless_linux_uses_the_file(self):
        (code, out, _), _ = self.set_prompted("access-key", runner=Runner(), platform="linux", tools=())
        self.assertEqual((code, out), (0, "stored access-key in file\n"))
        self.assertEqual(store.load_file(self.path), {"access-key": VALUE})

    def test_auto_on_windows_uses_the_file(self):
        (code, out, _), _ = self.set_prompted("access-key", runner=Runner(), platform="win32")
        self.assertEqual((code, out), (0, "stored access-key in file\n"))

    # ---- input handling
    def test_from_stdin_reads_one_line_without_a_tty(self):
        code, out, err = self.run_cli("config", "set", "access-key", "--store", "file", "--from-stdin",
                                      env=self.env, stdin=io.StringIO(VALUE + "\r\nsecond line\n"))
        self.assertEqual((code, out, err), (0, "stored access-key in file\n", ""))
        self.assertEqual(store.load_file(self.path), {"access-key": VALUE})

    def test_no_tty_without_from_stdin_is_refused(self):
        with mock.patch.object(cli.getpass, "getpass", side_effect=AssertionError("must not prompt")):
            code, out, err = self.run_cli("config", "set", "access-key", "--store", "file", env=self.env,
                                          stdin=io.StringIO(VALUE + "\n"))
        self.assertEqual(code, 2)
        self.assertIn("--from-stdin", err)
        self.assertFalse(self.path.exists())
        self.assertNotIn(VALUE, out + err)

    def test_value_on_the_command_line_is_impossible(self):
        for argv in (["access-key", VALUE], ["access-key", "--value", VALUE], ["access-key", "--store", "file", "-w", VALUE]):
            code, out, err = self.run_cli("config", "set", *argv, env=self.env, stdin=TTY(""))
            self.assertEqual(code, 2, argv)
        self.assertFalse(self.path.exists())

    def test_unknown_setting_and_store(self):
        self.assertEqual(self.run_cli("config", "set", "bogus", env=self.env, stdin=TTY(""))[0], 2)
        self.assertEqual(self.run_cli("config", "set", "access-key", "--store", "cloud", env=self.env, stdin=TTY(""))[0], 2)
        self.assertEqual(self.run_cli("config", "set", env=self.env)[0], 2)

    def test_empty_control_chars_and_bad_base_url_are_refused(self):
        for bad, name in (("", "access-key"), ("   ", "access-key"), ("a\tb", "secret-key"), ("a\x01b", "access-key"),
                          ("https://evil.example.com", "base-url")):
            (code, out, err), _ = self.set_prompted(name, "--store", "file", value=bad)
            self.assertEqual(code, 1, repr(bad))
            self.assertFalse(self.path.exists())
            self.assertNotIn("evil.example", out + err)
        code, out, err = self.run_cli("config", "set", "secret-key", "--store", "file", "--from-stdin",
                                      env=self.env, stdin=io.StringIO("\n"))
        self.assertEqual(code, 1)

    def test_valid_base_url_and_config_name_are_stored(self):
        self.set_prompted("base-url", "--store", "file", value="http://127.0.0.1:9/")
        self.set_prompted("config-name", "--store", "file", value="  demo  ")
        self.assertEqual(store.load_file(self.path), {"base-url": "http://127.0.0.1:9", "config-name": "demo"})

    def test_nothing_secret_in_any_output_of_set(self):
        outputs = []
        outputs += [self.set_prompted("secret-key", "--store", "file")[0]]
        outputs += [self.set_prompted("secret-key", "--store", "keychain", platform="linux", runner=Runner())[0]]
        outputs += [self.set_prompted("secret-key", "--store", "secret-service", platform="linux", runner=Runner(lambda c, k: (1, "", VALUE)))[0]]
        for _, out, err in outputs:
            self.assertNotIn(VALUE, out + err)

    # ---- unset
    def test_unset_file(self):
        self.set_prompted("access-key", "--store", "file", value="a")
        self.set_prompted("secret-key", "--store", "file", value="b")
        code, out, err = self.run_cli("config", "unset", "access-key", "--store", "file", env=self.env)
        self.assertEqual((code, out, err), (0, "removed access-key from file\n", ""))
        self.assertEqual(store.load_file(self.path), {"secret-key": "b"})
        code, out, _ = self.run_cli("config", "unset", "access-key", "--store", "file", env=self.env)
        self.assertEqual((code, out), (0, "access-key was not stored in file\n"))
        if POSIX:
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_unset_keychain_and_secret_service(self):
        runner = Runner(lambda c, k: (0, "", ""))
        with fake_platform("darwin", runner, ("security",)):
            code, out, _ = self.run_cli("config", "unset", "secret-key", "--store", "keychain", env=self.env)
        self.assertEqual((code, out), (0, "removed secret-key from keychain\n"))
        self.assertEqual(runner.calls[0][0], ["security", "delete-generic-password", "-s", "simlessly-cli", "-a", "secret-key"])
        runner = Runner(lambda c, k: (1, "", ""))
        with fake_platform("linux", runner):
            code, out, _ = self.run_cli("config", "unset", "secret-key", "--store", "secret-service", env=self.env)
        self.assertEqual((code, out), (0, "secret-key was not stored in secret-service\n"))
        self.assertEqual([c[1] for c, _ in runner.calls], ["lookup"])  # absent: nothing to clear
        present = [True]

        def handler(cmd, kw):
            if cmd[1] == "clear":
                present[0] = False
                return (0, "", "")
            return (0, "x\n", "") if present[0] else (1, "", "")
        runner = Runner(handler)
        with fake_platform("linux", runner):
            code, out, _ = self.run_cli("config", "unset", "secret-key", "--store", "secret-service", env=self.env)
        self.assertEqual((code, out), (0, "removed secret-key from secret-service\n"))
        self.assertEqual([c[1] for c, _ in runner.calls], ["lookup", "clear", "lookup"])
        self.assertEqual(runner.calls[1][0], ["secret-tool", "clear", "service", "simlessly-cli", "setting", "secret-key"])

    def test_unset_auto_on_headless_linux_targets_the_file(self):
        self.set_prompted("access-key", "--store", "file")
        with fake_platform("linux", Runner(), ()):
            code, out, _ = self.run_cli("config", "unset", "access-key", env=self.env)
        self.assertEqual((code, out), (0, "removed access-key from file\n"))


class PortabilityTests(unittest.TestCase):
    def test_stream_errors_replace_not_crash(self):
        # main_entry reconfigures the standard streams with errors="replace"
        class Stream(io.StringIO):
            reconfigured = None

            def reconfigure(self, **kw):
                Stream.reconfigured = kw

        with mock.patch.object(sys, "stdout", Stream()), mock.patch.object(sys, "stderr", Stream()), \
                mock.patch.object(cli, "main", return_value=0):
            with self.assertRaises(SystemExit):
                cli.main_entry()
        self.assertEqual(Stream.reconfigured, {"errors": "replace"})


if __name__ == "__main__":
    unittest.main()
