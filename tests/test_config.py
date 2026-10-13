import shutil
import subprocess
import sys
import unittest
from unittest import mock

import support  # noqa: F401
from simlessly_cli import config
from simlessly_cli.config import ConfigError, Settings, validate_base_url


class Keychain:
    def __init__(self, values):
        self.values, self.calls = values, []

    def __call__(self, account):
        self.calls.append(account)
        return self.values.get(account)


class SettingsTests(unittest.TestCase):
    def test_precedence_flag_env_keychain(self):
        kc = Keychain({"access-key": "from-keychain", "secret-key": "kc-secret", "config-name": "kc-config"})
        s = Settings({"SIMLESSLY_ACCESS_KEY": "from-env"}, kc, overrides={"config-name": "from-flag"})
        self.assertEqual((s.get("config-name").value, s.get("config-name").source), ("from-flag", "flag"))
        self.assertEqual((s.get("access-key").value, s.get("access-key").source), ("from-env", "env"))
        self.assertEqual((s.get("secret-key").value, s.get("secret-key").source), ("kc-secret", "keychain"))
        self.assertNotIn("access-key", kc.calls)  # env wins, Keychain not even asked

    def test_describe_never_contains_values(self):
        kc = Keychain({"secret-key": "SUPERSECRETVALUE"})
        s = Settings({"SIMLESSLY_ACCESS_KEY": "ACCESSVALUE"}, kc)
        text = repr(s.describe()) + repr(s.get("access-key")) + repr(s.get("secret-key"))
        self.assertNotIn("SUPERSECRETVALUE", text)
        self.assertNotIn("ACCESSVALUE", text)
        self.assertEqual(dict(s.describe())["access-key"], "set (env)")
        self.assertEqual(dict(s.describe())["secret-key"], "set (keychain)")
        self.assertEqual(dict(s.describe())["config-name"], "missing (optional)")

    def test_no_keychain_switch_and_none(self):
        kc = Keychain({"access-key": "x"})
        self.assertFalse(Settings({"SIMLESSLY_NO_KEYCHAIN": "1"}, kc).get("access-key").is_set)
        self.assertEqual(kc.calls, [])
        self.assertFalse(Settings({}, None).get("access-key").is_set)

    def test_require_message_has_no_value(self):
        with self.assertRaises(ConfigError) as cm:
            Settings({}, None).require("secret-key")
        self.assertIn("SIMLESSLY_SECRET_KEY", str(cm.exception))

    def test_secrets_lists_credentials_only_after_lookup(self):
        s = Settings({"SIMLESSLY_ACCESS_KEY": "AAAA1111", "SIMLESSLY_SECRET_KEY": "BBBB2222"}, None)
        self.assertEqual(s.secrets(), [])
        s.require("access-key"), s.require("secret-key")
        self.assertEqual(sorted(s.secrets()), ["AAAA1111", "BBBB2222"])


class KeychainCommandTests(unittest.TestCase):
    def test_exact_security_command(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="the-value\n", stderr="")

        with mock.patch.object(sys, "platform", "darwin"), mock.patch.object(shutil, "which", lambda n: "/usr/bin/security"):
            self.assertEqual(config.keychain_lookup("secret-key", runner=fake_run), "the-value")
        self.assertEqual(seen["cmd"], ["security", "find-generic-password", "-s", "simlessly-cli", "-a", "secret-key", "-w"])

    def test_missing_item_is_none(self):
        with mock.patch.object(sys, "platform", "darwin"), mock.patch.object(shutil, "which", lambda n: "/usr/bin/security"):
            run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 44, stdout="", stderr="could not be found")
            self.assertIsNone(config.keychain_lookup("x", runner=run))


class BaseUrlTests(unittest.TestCase):
    def test_accepted(self):
        self.assertEqual(validate_base_url("https://rsp.simlessly.com"), "https://rsp.simlessly.com")
        self.assertEqual(validate_base_url("https://rsp.simlessly.com/"), "https://rsp.simlessly.com")
        self.assertEqual(validate_base_url("http://127.0.0.1:8123"), "http://127.0.0.1:8123")
        self.assertEqual(validate_base_url("http://localhost:9/"), "http://localhost:9")
        self.assertEqual(validate_base_url("http://[::1]:9"), "http://[::1]:9")

    def test_refused(self):
        for bad in ("https://evil.example.com", "https://rsp.simlessly.com.evil.com", "http://rsp.simlessly.com",
                    "https://rsp.simlessly.com/api/v1", "https://rsp.simlessly.com?x=1", "https://rsp.simlessly.com#f",
                    "https://user:pw@rsp.simlessly.com", "https://rsp.simlessly.com:8443", "http://example.com",
                    "ftp://127.0.0.1", "http://127.0.0.1.evil.com", "http://127.0.0.1@evil.com", "rsp.simlessly.com", ""):
            with self.assertRaises(ConfigError, msg=bad):
                validate_base_url(bad)


if __name__ == "__main__":
    unittest.main()
