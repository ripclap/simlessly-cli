"""Credential stores: timeouts, no home directory, unset results, in-place file edits, shadowing notes,
UTF-8, descriptor-based reads, Keychain cleanup and optional settings. subprocess.run is faked (see test_store.fake_platform).
"""

import contextlib
import io
import json
import os
import pathlib
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import test_store as ts
from support import ACCESS, SECRET, CliTestCase
from simlessly_cli import cli, config, store

POSIX = ts.POSIX
Runner, fake_platform, write_cred_file, TmpMixin = ts.Runner, ts.fake_platform, ts.write_cred_file, ts.TmpMixin
VALUE = ts.VALUE
ICCID = "8999000000000000001"


def timeout(cmd, kw):
    raise subprocess.TimeoutExpired(cmd, kw["timeout"])


# ------------------------------------------------------------------ 1. keyring timeouts

class KeyringTimeoutTests(CliTestCase, TmpMixin):
    def setUp(self):
        super().setUp()
        self.path = self.make_tmp() / "creds"
        self.env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path)}
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n")

    def check(self, handler, *extra):
        with fake_platform("linux", Runner(handler)) as runner:
            result = self.run_cli("config", "check", *extra, env=self.env, keychain=config.keychain_lookup)
        return result, runner

    def test_timeout_is_remembered_and_reported(self):
        (code, out, err), runner = self.check(timeout)
        self.assertEqual(len(runner.calls), 1)  # not one 5 s wait per setting
        self.assertEqual((code, err), (0, ""))
        self.assertIn("secret-service: timed out (keyring locked?)", out)
        self.assertEqual(out.count(f"set (file {self.path})"), 2)
        self.assertIn("Ready.", out)

    def test_dbus_failure_is_remembered_and_reported(self):
        (code, out, err), runner = self.check(lambda c, k: (1, "", "Cannot autolaunch D-Bus without X11"))
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("could not reach the keyring", out)
        self.assertNotIn("autolaunch", out)  # tool text is not forwarded

    def test_plain_absence_is_not_a_problem_and_asks_every_setting(self):
        (code, out, err), runner = self.check(lambda c, k: (1, "", ""))
        self.assertEqual(len(runner.calls), 5)  # access-key, secret-key, config-name, base-url, portal-token
        self.assertNotIn("keyring problem", out)

    def test_json_carries_the_keyring_error(self):
        (code, out, _), _ = self.check(timeout, "--json")
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(data["os_store_error"], store.TIMED_OUT_MESSAGE)

    def test_commands_skip_the_keyring_after_the_first_timeout(self):
        self.server.routes["/api/v1/config/list"] = lambda r: ts.ok({"configs": ["a"]})
        env = {**self.env, "SIMLESSLY_BASE_URL": self.server.url}
        with fake_platform("linux", Runner(timeout)) as runner:
            code, out, err = self.run_cli("configs", "list", env=env, keychain=config.keychain_lookup)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(runner.calls), 1)

    def test_store_failures_point_at_the_file_store(self):
        for handler in (timeout, lambda c, k: (1, "", "boom"), lambda c, k: (_ for _ in ()).throw(OSError("x"))):
            with fake_platform("linux", Runner(handler)):
                code, out, err = self.run_cli_set("secret-key", "--store", "secret-service")
            self.assertEqual(code, 1)
            self.assertIn("--store file", err)

    def run_cli_set(self, *argv):
        with mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: VALUE):
            return self.run_cli("config", "set", *argv, env=self.env, stdin=ts.TTY(""))

    def test_lookup_keeps_the_short_limit_and_store_gets_the_long_one(self):
        self.assertLessEqual(store.TOOL_TIMEOUT, 5)
        self.assertGreaterEqual(store.STORE_TIMEOUT, 60)


# ------------------------------------------------------------------ 2. no home directory

class NoHomeTests(CliTestCase, TmpMixin):
    def no_home(self):
        return mock.patch.object(pathlib.Path, "home", side_effect=RuntimeError("Could not determine home directory."))

    def test_credentials_path_raises_a_store_error(self):
        with self.no_home():
            with self.assertRaises(store.StoreError) as cm:
                store.credentials_path({})
        self.assertIn("SIMLESSLY_CREDENTIALS_FILE", str(cm.exception))
        with self.assertRaises(store.StoreError):
            store.credentials_path({"SIMLESSLY_CREDENTIALS_FILE": "~no-such-user-xyz/creds"})

    def test_env_only_with_no_credentials_file_switch_never_needs_home(self):
        env = {"SIMLESSLY_ACCESS_KEY": ACCESS, "SIMLESSLY_SECRET_KEY": SECRET, "SIMLESSLY_NO_CREDENTIALS_FILE": "1",
               "SIMLESSLY_NO_KEYCHAIN": "1"}
        with self.no_home():
            code, out, err = self.run_cli("config", "check", env=env)
            self.assertEqual((code, err), (0, ""), out)
            self.assertIn("Ready.", out)
            code, out, err = self.run_cli("config", "check", "--json", env=env)
            self.assertEqual(code, 0)
            self.assertIsNone(json.loads(out)["credentials_file"])

    def test_env_only_without_the_switch_just_has_no_file(self):
        self.server.routes["/api/v1/config/list"] = lambda r: ts.ok({"configs": ["a"]})
        env = {**self.env, "SIMLESSLY_NO_KEYCHAIN": "1"}
        env.pop("SIMLESSLY_NO_CREDENTIALS_FILE")
        with self.no_home():
            code, out, err = self.run_cli("configs", "list", env=env)
            self.assertEqual((code, err), (0, ""))
            self.assertAllSigned()
            code, out, err = self.run_cli("config", "check", env=env)
            self.assertEqual((code, err), (0, ""))
            self.assertNotIn("Traceback", out)

    def test_config_set_to_the_file_says_what_is_missing(self):
        env = {"SIMLESSLY_NO_KEYCHAIN": "1"}
        with self.no_home(), mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: VALUE):
            code, out, err = self.run_cli("config", "set", "access-key", "--store", "file", env=env, stdin=ts.TTY(""))
        self.assertEqual(code, 1)
        self.assertIn("no home directory", err)
        self.assertIn("SIMLESSLY_CREDENTIALS_FILE", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn(VALUE, out + err)


# ------------------------------------------------------------------ 3. unset results

class UnsetResultTests(CliTestCase, TmpMixin):
    def unset(self, platform, runner, store_name, tools):
        env = {"SIMLESSLY_NO_KEYCHAIN": "1", "SIMLESSLY_CREDENTIALS_FILE": str(self.make_tmp() / "c")}
        with fake_platform(platform, runner, tools):
            return self.run_cli("config", "unset", "access-key", "--store", store_name, env=env)

    def test_keychain_only_exit_44_means_not_stored(self):
        code, out, err = self.unset("darwin", Runner(lambda c, k: (44, "", "")), "keychain", ("security",))
        self.assertEqual((code, out, err), (0, "access-key was not stored in keychain\n", ""))

    def test_keychain_other_failures_are_errors(self):
        for rc, text in ((51, "User interaction is not allowed."), (1, ""), (2, "x")):
            code, out, err = self.unset("darwin", Runner(lambda c, k: (rc, "", text)), "keychain", ("security",))
            self.assertEqual(code, 1, rc)
            self.assertIn("could not remove access-key", err)
            self.assertNotIn("was not stored", out + err)
        for handler in (timeout, lambda c, k: (_ for _ in ()).throw(OSError("x"))):
            code, out, err = self.unset("darwin", Runner(handler), "keychain", ("security",))
            self.assertEqual(code, 1)

    def test_secret_service_failures_are_errors(self):
        cases = {
            "dbus on lookup": lambda c, k: (1, "", "Cannot autolaunch D-Bus without X11"),
            "timeout on lookup": timeout,
            "OSError": lambda c, k: (_ for _ in ()).throw(OSError("x")),
        }
        for label, handler in cases.items():
            runner = Runner(handler)
            code, out, err = self.unset("linux", runner, "secret-service", ("secret-tool",))
            self.assertEqual(code, 1, label)
            self.assertNotIn("was not stored", out + err, label)
            self.assertNotIn("removed", out, label)

    def test_secret_service_clear_failure_and_phantom_success(self):
        def clear_fails(cmd, kw):
            return (1, "", "locked") if cmd[1] == "clear" else (0, "x\n", "")
        code, out, err = self.unset("linux", Runner(clear_fails), "secret-service", ("secret-tool",))
        self.assertEqual(code, 1)
        self.assertIn("still stored", err)
        phantom = lambda cmd, kw: (0, "", "") if cmd[1] == "clear" else (0, "x\n", "")  # clear "works", item remains
        code, out, err = self.unset("linux", Runner(phantom), "secret-service", ("secret-tool",))
        self.assertEqual(code, 1)
        self.assertNotIn("removed access-key", out)

    def test_secret_service_value_from_lookup_never_printed(self):
        state = {"gone": False}

        def handler(cmd, kw):
            if cmd[1] == "clear":
                state["gone"] = True
                return (0, "", "")
            return (1, "", "") if state["gone"] else (0, VALUE + "\n", "")
        code, out, err = self.unset("linux", Runner(handler), "secret-service", ("secret-tool",))
        self.assertEqual((code, out), (0, "removed access-key from secret-service\n"))
        self.assertNotIn(VALUE, out + err)


# ------------------------------------------------------------------ 4. in-place file edits

COMMENTED = ("# my notes\n"
             "[default]\n"
             "access-key = A1\n"
             "config-name =\n"
             "\n"
             "[staging]\n"
             "# staging keys\n"
             "access-key = STAGE\n"
             "secret-key = STAGESECRET\n")


class InPlaceEditTests(unittest.TestCase, TmpMixin):
    def setUp(self):
        self.path = self.make_tmp() / "creds"

    def test_set_keeps_comments_sections_and_blank_keys(self):
        write_cred_file(self.path, COMMENTED)
        store.file_store(self.path, "secret-key", "NEWSECRET")
        self.assertEqual(self.path.read_text(), COMMENTED.replace("config-name =\n", "config-name =\nsecret-key = NEWSECRET\n"))
        store.file_store(self.path, "access-key", "A2")
        self.assertIn("access-key = A2\n", self.path.read_text())
        text = self.path.read_text()
        self.assertTrue(text.startswith("# my notes\n[default]\n"))
        self.assertIn("[staging]\n# staging keys\naccess-key = STAGE\nsecret-key = STAGESECRET\n", text)
        self.assertIn("config-name =\n", text)

    def test_unrelated_sections_and_comments_are_kept(self):
        write_cred_file(self.path, "# my notes\n[default]\naccess-key=A1\n[staging]\naccess-key=STAGE\nsecret-key=STAGESECRET\n")
        store.file_store(self.path, "config-name", "x")
        self.assertEqual(self.path.read_text(),
                         "# my notes\n[default]\naccess-key=A1\nconfig-name = x\n[staging]\naccess-key=STAGE\nsecret-key=STAGESECRET\n")

    def test_unset_removes_only_that_line(self):
        write_cred_file(self.path, COMMENTED)
        self.assertTrue(store.file_delete(self.path, "access-key"))
        self.assertEqual(self.path.read_text(), COMMENTED.replace("access-key = A1\n", "", 1))
        self.assertFalse(store.file_delete(self.path, "access-key"))  # [staging] has one; [default] no longer
        self.assertTrue(store.file_delete(self.path, "config-name"))  # a blank-valued key is still a key

    def test_unset_of_a_missing_file_writes_nothing(self):
        self.assertFalse(store.file_delete(self.path, "access-key"))
        self.assertFalse(self.path.exists())

    def test_no_default_section_is_appended_and_case_and_continuations_are_handled(self):
        write_cred_file(self.path, "[other]\nx = 1")
        store.file_store(self.path, "access-key", "A")
        self.assertEqual(self.path.read_text(), "[other]\nx = 1\n\n[default]\naccess-key = A\n")
        write_cred_file(self.path, "[default]\nAccess-Key = old\n  continued\nsecret-key = s\n")
        store.file_store(self.path, "access-key", "new")
        self.assertEqual(self.path.read_text(), "[default]\naccess-key = new\nsecret-key = s\n")

    def test_new_key_goes_before_the_next_section_not_after_trailing_blank_lines(self):
        write_cred_file(self.path, "[default]\na = 1\n\n\n[x]\nb = 2\n")
        store.file_store(self.path, "access-key", "A")
        self.assertEqual(self.path.read_text(), "[default]\na = 1\naccess-key = A\n\n\n[x]\nb = 2\n")

    def test_an_edit_that_would_change_anything_else_writes_nothing(self):
        write_cred_file(self.path, COMMENTED)
        with mock.patch.object(store, "_edit_default", return_value="[default]\naccess-key = A1\n"):
            with self.assertRaises(store.StoreError) as cm:
                store.file_store(self.path, "secret-key", VALUE)
        self.assertIn("cannot edit safely", str(cm.exception))
        self.assertNotIn(VALUE, str(cm.exception))
        self.assertEqual(self.path.read_text(), COMMENTED)

    def test_symlinked_file_stays_a_symlink_and_the_target_is_updated(self):
        if not POSIX:
            self.skipTest("symlinks")
        target_dir = self.make_tmp()
        target = write_cred_file(target_dir / "real-creds", "# dotfiles\n[default]\naccess-key = A\n")
        link = self.path
        link.symlink_to(target)
        store.file_store(link, "secret-key", "S")
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(), "# dotfiles\n[default]\naccess-key = A\nsecret-key = S\n")
        self.assertEqual(store.load_file(link), {"access-key": "A", "secret-key": "S"})
        self.assertEqual([p.name for p in target_dir.iterdir()], ["real-creds"])
        store.file_delete(link, "secret-key")
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(), "# dotfiles\n[default]\naccess-key = A\n")

    def test_symlink_to_an_unsafe_file_is_refused(self):
        if not POSIX:
            self.skipTest("symlinks")
        target = write_cred_file(self.make_tmp() / "real", "[default]\naccess-key = A\n", 0o644)
        self.path.symlink_to(target)
        with self.assertRaises(store.StoreError):
            store.file_store(self.path, "secret-key", "S")
        self.assertEqual(target.read_text(), "[default]\naccess-key = A\n")


# ------------------------------------------------------------------ 5. shadowing note

class ShadowNoteTests(CliTestCase, TmpMixin):
    def setUp(self):
        super().setUp()
        self.path = self.make_tmp() / "creds"

    def set_value(self, *argv, env, platform=None, runner=None, value=VALUE, tools=("secret-tool",)):
        ctx = fake_platform(platform, runner, tools) if platform else contextlib.nullcontext()
        with ctx, mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: value):
            return self.run_cli("config", "set", *argv, env=env, stdin=ts.TTY(""), keychain=config.keychain_lookup)

    def test_environment_variable_wins(self):
        env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path), "SIMLESSLY_NO_KEYCHAIN": "1", "SIMLESSLY_ACCESS_KEY": ACCESS}
        code, out, err = self.set_value("access-key", "--store", "file", env=env, value="rotated-key")
        self.assertEqual((code, out), (0, "stored access-key in file\n"))
        self.assertIn("SIMLESSLY_ACCESS_KEY", err)
        self.assertIn("takes precedence", err)
        self.assertIn("is not used", err)
        self.assertNoSecrets(out, err, extra=("rotated-key",))

    def test_keyring_wins_over_the_file(self):
        env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path)}
        runner = Runner(lambda c, k: (0, "old-key\n", ""))
        code, out, err = self.set_value("access-key", "--store", "file", env=env, platform="linux", runner=runner)
        self.assertEqual((code, out), (0, "stored access-key in file\n"))
        self.assertIn("keyring", err)
        self.assertIn("config unset access-key --store secret-service", err)
        self.assertNotIn("old-key", out + err)
        self.assertNotIn(VALUE, out + err)

    def test_keychain_wins_over_the_file_on_macos(self):
        env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path)}
        runner = Runner(lambda c, k: (0, "old\n", ""))
        code, out, err = self.set_value("access-key", "--store", "file", env=env, platform="darwin", runner=runner, tools=("security",))
        self.assertIn("Keychain", err)
        self.assertIn("--store keychain", err)

    def test_no_note_when_the_value_just_stored_is_the_one_in_use(self):
        env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path), "SIMLESSLY_NO_KEYCHAIN": "1"}
        code, out, err = self.set_value("access-key", "--store", "file", env=env)
        self.assertEqual((code, out, err), (0, "stored access-key in file\n", ""))

    def test_no_note_for_a_setting_that_is_only_in_the_store_written(self):
        env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path), "SIMLESSLY_ACCESS_KEY": ACCESS, "SIMLESSLY_NO_KEYCHAIN": "1"}
        code, out, err = self.set_value("secret-key", "--store", "file", env=env, value=SECRET)
        self.assertEqual(err, "")


# ------------------------------------------------------------------ 6. UTF-8 and encoding errors

class EncodingTests(CliTestCase, TmpMixin):
    def setUp(self):
        super().setUp()
        self.path = self.make_tmp() / "creds"
        self.env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path)}

    def test_subprocess_text_is_utf8_whatever_the_locale(self):
        runner = Runner(lambda c, k: (1, "", "") if c[1] == "lookup" else (0, "", ""))
        with fake_platform("linux", runner):
            store.secret_service_lookup("access-key")
            store.secret_service_store("access-key", "v", None)
        with fake_platform("darwin", Runner(lambda c, k: (44, "", "")), ("security",)) as r2:
            store.keychain_lookup("access-key")
        for _, kw in runner.calls + r2.calls:
            self.assertEqual(kw["encoding"], "utf-8")

    def test_encode_failure_is_a_clean_error_without_codec_text(self):
        def handler(cmd, kw):
            raise UnicodeEncodeError("latin-1", "SECRETpart€TAIL", 10, 11, "ordinal not in range(256)")
        with fake_platform("linux", Runner(handler)), \
                mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: "config-€-name"):
            code, out, err = self.run_cli("config", "set", "config-name", "--store", "secret-service", env=self.env, stdin=ts.TTY(""))
        self.assertEqual(code, 1)
        self.assertIn("could not store config-name", err)
        self.assertNotIn("unexpected", err)
        self.assertNotIn("latin-1", err)
        self.assertNotIn("€", out + err)

    def test_decode_failure_on_lookup_falls_through(self):
        write_cred_file(self.path, f"[default]\naccess-key = {ACCESS}\nsecret-key = {SECRET}\n")

        def handler(cmd, kw):
            raise UnicodeDecodeError("ascii", b"\xe2\x82\xac", 0, 1, "ordinal not in range(128)")
        with fake_platform("linux", Runner(handler)) as runner:
            code, out, err = self.run_cli("config", "check", env=self.env, keychain=config.keychain_lookup)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(runner.calls), 5)  # an undecodable answer is "not there", not "keyring broken"
        with fake_platform("darwin", Runner(handler), ("security",)):
            self.assertIsNone(store.keychain_lookup("access-key"))

    def test_non_ascii_keys_are_refused_before_any_store(self):
        runner = Runner()
        with fake_platform("linux", runner), \
                mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: "SECRETpart€TAIL"):
            code, out, err = self.run_cli("config", "set", "secret-key", "--store", "secret-service", env=self.env, stdin=ts.TTY(""))
        self.assertEqual(code, 1)
        self.assertIn("non-ASCII", err)
        self.assertNotIn("SECRETpart", out + err)
        self.assertEqual(runner.calls, [])


# ------------------------------------------------------------------ 7. one open, checked on the descriptor

class DescriptorReadTests(unittest.TestCase, TmpMixin):
    def test_file_is_opened_once_without_following_symlinks(self):
        path = write_cred_file(self.make_tmp() / "creds", "[default]\naccess-key = A\n")
        opened = []
        real_open = os.open
        spy = lambda p, flags, *a, **k: opened.append((p, flags)) or real_open(p, flags, *a, **k)
        with mock.patch.object(os, "open", spy):
            self.assertEqual(store.load_file(path), {"access-key": "A"})
        self.assertEqual(len(opened), 1)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(opened[0][1] & os.O_NOFOLLOW)

    def test_a_symlink_swapped_in_after_resolution_is_not_followed(self):
        if not POSIX:
            self.skipTest("symlinks")
        tmp = self.make_tmp()
        target = write_cred_file(tmp / "target", "[default]\naccess-key = attacker\n")
        link = tmp / "creds"
        link.symlink_to(target)
        with mock.patch.object(store, "_real_path", return_value=str(link)):  # the race: resolved, then swapped
            with self.assertRaises(store.StoreError):
                store.load_file(link)

    def test_symlinked_credentials_file_is_read_once_resolved(self):
        if not POSIX:
            self.skipTest("symlinks")
        tmp = self.make_tmp()
        target = write_cred_file(tmp / "target", "[default]\naccess-key = A\n")
        (tmp / "creds").symlink_to(target)
        self.assertEqual(store.load_file(tmp / "creds"), {"access-key": "A"})


# ------------------------------------------------------------------ 8. Keychain cleanup

class KeychainCleanupTests(CliTestCase, TmpMixin):
    def setUp(self):
        super().setUp()
        self.env = {"SIMLESSLY_NO_KEYCHAIN": "1", "SIMLESSLY_CREDENTIALS_FILE": str(self.make_tmp() / "c")}

    def set_keychain(self, runner, value=VALUE):
        with fake_platform("darwin", runner, ("security",)), \
                mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: value):
            return self.run_cli("config", "set", "config-name", "--store", "keychain", env=self.env, stdin=ts.TTY(""))

    def test_mismatch_deletes_the_item_again(self):
        runner = Runner(lambda cmd, kw: (0, "mangled\n", "") if cmd[1] == "find-generic-password" else (0, "", ""))
        code, out, err = self.set_keychain(runner)
        self.assertEqual(code, 1)
        self.assertIn("read back", err)
        self.assertIn("removed again", err)
        deletes = [c for c, _ in runner.calls if c[1] == "delete-generic-password"]
        self.assertEqual(deletes, [["security", "delete-generic-password", "-s", "simlessly-cli", "-a", "config-name"]])
        self.assertNotIn(VALUE, out + err)

    def test_mismatch_and_failed_cleanup_says_so(self):
        def handler(cmd, kw):
            if cmd[1] == "find-generic-password":
                return (0, "mangled\n", "")
            if cmd[1] == "delete-generic-password":
                return (51, "", "User interaction is not allowed.")
            return (0, "", "")
        code, out, err = self.set_keychain(Runner(handler))
        self.assertEqual(code, 1)
        self.assertIn("could not be removed", err)
        self.assertIn("config unset config-name --store keychain", err)

    def test_non_ascii_value_is_refused_before_writing(self):
        runner = Runner()
        code, out, err = self.set_keychain(runner, value="café")
        self.assertEqual(code, 1)
        self.assertIn("--store file", err)
        self.assertEqual(runner.calls, [])


# ------------------------------------------------------------------ 9. optional settings and a refused file

class OptionalSettingsTests(CliTestCase, TmpMixin):
    def setUp(self):
        super().setUp()
        if not POSIX:
            self.skipTest("POSIX permissions")
        self.path = self.make_tmp() / "creds"
        write_cred_file(self.path, "[default]\nbase-url = http://127.0.0.1:9\nconfig-name = from-file\n", 0o644)
        self.env = {"SIMLESSLY_CREDENTIALS_FILE": str(self.path)}

    def keychain_handler(self, cmd, kw):
        if cmd[:2] == ["security", "find-generic-password"] and cmd[5] in ("access-key", "secret-key"):
            return (0, (ACCESS if cmd[5] == "access-key" else SECRET) + "\n", "")
        return (44, "", "")

    def test_refused_file_is_a_warning_when_the_keychain_has_the_credentials(self):
        with fake_platform("darwin", Runner(self.keychain_handler), ("security",)):
            code, out, err = self.run_cli("profile", "expire", ICCID, env=self.env, keychain=config.keychain_lookup)
        self.assertEqual(code, 2, err)  # a dry run, as before
        self.assertIn("Dry run", out)
        self.assertIn("https://rsp.simlessly.com", out)  # the default, not the refused file's base-url
        self.assertNotIn("127.0.0.1:9", out)
        self.assertIn("warning:", err)
        self.assertIn("chmod 600", err)
        self.assertIn("optional settings", err)
        self.assertNoSecrets(out, err)

    def test_check_reports_the_file_once_and_stays_ready(self):
        with fake_platform("darwin", Runner(self.keychain_handler), ("security",)):
            code, out, err = self.run_cli("config", "check", env=self.env, keychain=config.keychain_lookup)
        self.assertEqual(code, 0, out)
        self.assertEqual(err, "")
        self.assertEqual(out.count("chmod 600"), 1)
        self.assertIn("credentials file refused", out)
        self.assertIn("Ready.", out)

    def test_required_settings_still_hard_fail(self):
        with fake_platform("darwin", Runner(lambda c, k: (44, "", "")), ("security",)):
            code, out, err = self.run_cli("configs", "list", env=self.env, keychain=config.keychain_lookup)
        self.assertEqual(code, 1)
        self.assertIn("chmod 600", err)


if __name__ == "__main__":
    unittest.main()
