import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import support
from support import AC, ACCESS, EID, ICCID, KI, OPC, SECRET, CliTestCase, envelope, ok

ROOT = Path(__file__).resolve().parent.parent


class ErrorTests(CliTestCase):
    def test_vendor_error_envelope_on_200(self):
        self.server.routes["/api/v1/profile/detail"] = lambda r: (200, envelope(None, False, "profile not found", "E1001"), {})
        code, out, err = self.run_cli("profile", "show", ICCID)
        self.assertEqual(code, 1)
        self.assertIn("Simlessly refused the request: profile not found (code E1001)", err)

    def test_http_error_with_envelope(self):
        self.server.routes["/api/v1/profile/detail"] = lambda r: (400, envelope(None, False, "bad iccid", "E0001"), {})
        code, _, err = self.run_cli("profile", "show", ICCID)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 400: bad iccid", err)

    def test_bad_signature_is_a_clean_error(self):
        env = {**self.env, "SIMLESSLY_SECRET_KEY": "the-wrong-secret-value"}
        code, _, err = self.run_cli("profile", "show", ICCID, env=env)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 401", err)
        self.assertNotIn("the-wrong-secret-value", err)

    def test_success_not_boolean_is_unreadable(self):
        self.server.routes["/api/v1/profile/detail"] = lambda r: (200, {"obj": {}, "success": "true"}, {})
        code, _, err = self.run_cli("profile", "show", ICCID)
        self.assertEqual(code, 1)  # read-only: no unknown-outcome exit
        self.assertIn("not a result envelope", err)

    def test_non_json_body(self):
        self.server.routes["/api/v1/profile/detail"] = lambda r: (200, b"<html>gateway</html>", {})
        code, _, err = self.run_cli("profile", "show", ICCID)
        self.assertEqual(code, 1)
        self.assertIn("unreadable answer", err)

    def test_vendor_message_is_scrubbed(self):
        msg = f"cannot use {AC} for eid {EID}"
        self.server.routes["/api/v1/profile/detail"] = lambda r: (200, envelope(None, False, msg, "E1"), {})
        _, out, err = self.run_cli("profile", "show", ICCID)
        self.assertNotIn(AC, err)
        self.assertNotIn(EID, err)

    def test_connection_refused(self):
        env = {**self.env, "SIMLESSLY_BASE_URL": "http://127.0.0.1:1"}
        code, _, err = self.run_cli("configs", "list", env=env)
        self.assertEqual(code, 1)
        self.assertIn("could not connect", err)

    def test_refused_origin_never_connects(self):
        for url in ("https://evil.example.com", "https://rsp.simlessly.com.evil.com", "http://example.com"):
            code, _, err = self.run_cli("configs", "list", "--base-url", url)
            self.assertEqual(code, 1, url)
            self.assertIn("base URL refused", err)

    def test_missing_credentials_message(self):
        code, _, err = self.run_cli("configs", "list", env={"SIMLESSLY_BASE_URL": self.server.url, "SIMLESSLY_NO_KEYCHAIN": "1"})
        self.assertEqual(code, 1)
        self.assertIn("access-key is not set", err)
        self.assertEqual(self.server.requests, [])

    def test_keychain_credentials_are_used(self):
        kc = {"access-key": ACCESS, "secret-key": SECRET}.get
        self.server.routes["/api/v1/config/list"] = lambda r: ok({"configs": ["a"]})
        env = {"SIMLESSLY_BASE_URL": self.server.url}
        code, out, err = self.run_cli("configs", "list", env=env, keychain=kc)
        self.assertEqual(code, 0, err)
        self.assertAllSigned()


class TimeoutAndOutcomeTests(CliTestCase):
    def slow(self, path):
        self.server.routes[path] = lambda r: (200, envelope(None), {}, 1.5)

    def test_read_timeout(self):
        self.slow("/api/v1/profile/detail")
        code, _, err = self.run_cli("profile", "show", ICCID, "--timeout", "0.3")
        self.assertEqual(code, 1)
        self.assertIn("no answer within 0.3s", err)

    def test_mutation_timeout_is_unknown_and_not_retried(self):
        self.slow("/api/v1/profile/delete")
        code, _, err = self.run_cli("profile", "delete", ICCID, "--yes", "--timeout", "0.3")
        self.assertEqual(code, 3)
        self.assertIn("OUTCOME UNKNOWN", err)
        self.assertIn("Nothing was retried", err)
        self.assertEqual(len(self.server.requests), 1)

    def test_mutation_500_is_unknown_and_not_retried(self):
        self.server.routes["/api/v1/profile/expired"] = lambda r: (500, envelope(None, False, "boom", "E5"), {})
        code, _, err = self.run_cli("profile", "expire", ICCID, "--yes")
        self.assertEqual(code, 3)
        self.assertEqual(len(self.server.requests), 1)

    def test_mutation_4xx_and_refusal_are_definite(self):
        self.server.routes["/api/v1/profile/expired"] = lambda r: (400, envelope(None, False, "no", "E1"), {})
        self.server.routes["/api/v1/profile/delete"] = lambda r: (200, envelope(None, False, "no", "E1"), {})
        for argv in (["profile", "expire", ICCID, "--yes"], ["profile", "delete", ICCID, "--yes"]):
            code, _, err = self.run_cli(*argv)
            self.assertEqual(code, 1)
            self.assertNotIn("OUTCOME UNKNOWN", err)

    def test_mutation_redirect_is_unknown_and_not_followed(self):
        self.server.routes["/api/v1/profile/delete"] = lambda r: (302, b"", {"Location": self.server.url + "/elsewhere"})
        code, _, err = self.run_cli("profile", "delete", ICCID, "--yes")
        self.assertEqual(code, 3)
        self.assertIn("redirect", err)
        self.assertEqual([r.path for r in self.server.requests], ["/api/v1/profile/delete"])

    def test_oversized_answer(self):
        self.server.routes["/api/v1/profile/delete"] = lambda r: (200, b"x" * ((1 << 20) + 10), {})
        code, _, err = self.run_cli("profile", "delete", ICCID, "--yes")
        self.assertEqual(code, 3)
        self.assertIn("1 MiB", err)

    def test_mutation_unreadable_answer_is_unknown(self):
        self.server.routes["/api/v1/profile/delete"] = lambda r: (200, b"", {})
        code, _, err = self.run_cli("profile", "delete", ICCID, "--yes")
        self.assertEqual(code, 3)
        self.assertIn("not a result envelope", err)

    def test_connection_refused_mutation_is_definite(self):
        env = {**self.env, "SIMLESSLY_BASE_URL": "http://127.0.0.1:1"}
        code, _, err = self.run_cli("profile", "delete", ICCID, "--yes", env=env)
        self.assertEqual(code, 1)


class RedactionTests(CliTestCase):
    def test_debug_output_is_redacted_everywhere(self):
        self.env.update({"SIMLESSLY_SIM_KI": KI, "SIMLESSLY_SIM_OPC": OPC})
        self.server.routes["/api/v2/ac/generate"] = lambda r: ok({"iccid": ICCID, "activationCode": AC})
        self.server.routes["/api/v1/profile/detail"] = lambda r: ok(
            {"iccid": ICCID, "eid": EID, "status": "ENABLED", "ac": AC, "imsi": "001010000000001"})
        code1, out1, err1 = self.run_cli(*"ac generate --config c --iccid".split(), ICCID, "--imsi", "001010000000001",
                                         "--yes", "--debug")
        code2, out2, err2 = self.run_cli("profile", "show", ICCID, "--debug")
        self.assertEqual((code1, code2), (0, 0))
        signatures = [r.headers["Signature"] for r in self.server.requests]
        self.assertEqual(len(signatures), 2)
        for text in (err1, err2, out2):
            self.assertNoSecrets(text, extra=signatures + [AC, EID])
        self.assertNotIn(AC, err2 + out2)
        self.assertIn("[redacted]", err1)
        self.assertIn("> POST " + self.server.url + "/api/v2/ac/generate", err1)
        self.assertIn("< HTTP 200", err1)
        self.assertNoSecrets(out1, extra=signatures)

    def test_errors_never_contain_credentials(self):
        env = {**self.env, "SIMLESSLY_BASE_URL": "http://127.0.0.1:1"}
        _, out, err = self.run_cli("configs", "list", "--debug", env=env)
        self.assertNoSecrets(out, err)


class FakeConnection:
    """Stands in for http.client.HTTPConnection: request() succeeds, getresponse() raises."""
    error: BaseException = ConnectionAbortedError("aborted")
    request_error: BaseException | None = None

    def __init__(self, *a, **k):
        pass

    def request(self, *a, **k):
        if self.request_error:
            raise self.request_error

    def getresponse(self):
        raise self.error

    def close(self):
        pass


class AfterSendFailureTests(CliTestCase):
    def run_with(self, error, argv=("profile", "delete", ICCID, "--yes"), request_error=None):
        from unittest import mock
        conn = type("Conn", (FakeConnection,), {"error": error, "request_error": request_error})
        with mock.patch("simlessly_cli.client.http.client.HTTPConnection", conn):
            return self.run_cli(*argv)

    def test_oserrors_after_the_request_was_written_are_outcome_unknown(self):
        import ssl
        for error in (ConnectionAbortedError("aborted"), ssl.SSLError("decryption failed or bad record mac"),
                      OSError("weird")):
            for argv in (("profile", "delete", ICCID, "--yes"), ("order", "cancel", ICCID, "--yes")):
                with self.subTest(error=type(error).__name__, argv=argv[:2]):
                    code, _, err = self.run_with(error, argv)
                    self.assertEqual(code, 3)
                    self.assertIn("OUTCOME UNKNOWN", err)
                    self.assertNotIn("could not connect", err)

    def test_the_same_errors_on_a_read_are_a_plain_failure(self):
        code, _, err = self.run_with(ConnectionAbortedError("aborted"), ("profile", "show", ICCID))
        self.assertEqual(code, 1)
        self.assertNotIn("OUTCOME UNKNOWN", err)

    def test_oserror_before_the_request_finished_is_still_a_definite_connect_failure(self):
        code, _, err = self.run_with(None, request_error=ConnectionRefusedError("refused"))
        self.assertEqual(code, 1)
        self.assertIn("could not connect", err)
        self.assertNotIn("OUTCOME UNKNOWN", err)


class CredentialShapeTests(CliTestCase):
    def test_control_character_in_access_key_is_a_clean_error_not_a_traceback(self):
        for bad in ("FAKEACCESS\nKEYPART", "FAKEACCESS\r\nX-Evil: 1", "FAKE\tKEY"):
            with self.subTest(bad=bad):
                env = {**self.env, "SIMLESSLY_ACCESS_KEY": bad}
                code, out, err = self.run_cli("configs", "list", env=env)
                self.assertEqual(code, 1)
                self.assertIn("control character", err)
                self.assertNotIn("KEYPART", out + err)
                self.assertNotIn("Traceback", err)
                self.assertEqual(self.server.requests, [])

    def test_control_character_in_secret_key_is_refused_without_echo(self):
        env = {**self.env, "SIMLESSLY_SECRET_KEY": "SECRETPART1\nSECRETPART2"}
        code, out, err = self.run_cli("profile", "delete", ICCID, "--yes", env=env)
        self.assertEqual(code, 1)
        self.assertNotIn("SECRETPART", out + err)
        self.assertEqual(self.server.requests, [])

    def test_non_latin1_access_key_never_leaks_through_a_traceback(self):
        env = {**self.env, "SIMLESSLY_ACCESS_KEY": "KEY\u2603SNOWMAN"}
        code, out, err = self.run_cli("configs", "list", env=env)
        self.assertEqual(code, 1)
        self.assertNotIn("SNOWMAN", out + err)
        self.assertNotIn("Traceback", err)

    def test_last_resort_handler_prints_no_traceback_and_flags_mutations(self):
        from unittest import mock
        boom = ValueError("odd failure with " + SECRET)
        with mock.patch("simlessly_cli.client.Client.post", side_effect=boom):
            code, out, err = self.run_cli("configs", "list")
            self.assertEqual(code, 1)
            self.assertNotIn("Traceback", err)
            self.assertNotIn(SECRET, out + err)
            self.assertIn("unexpected ValueError", err)
            code, out, err = self.run_cli("profile", "delete", ICCID, "--yes")
            self.assertEqual(code, 3)
            self.assertIn("OUTCOME UNKNOWN", err)
            self.assertNotIn(SECRET, out + err)


class ParserHardeningTests(CliTestCase):
    def test_abbreviated_yes_does_not_arm_a_send(self):
        for flag in ("--y", "--ye"):
            with self.subTest(flag=flag):
                code, _, err = self.run_cli("profile", "delete", ICCID, flag)
                self.assertEqual(code, 2)
                self.assertIn("unrecognized", err)
                self.assertEqual(self.server.requests, [])

    def test_abbreviations_are_off_everywhere(self):
        self.assertEqual(self.run_cli("--vers")[0], 2)
        self.assertEqual(self.run_cli("configs", "list", "--pag", "1")[0], 2)
        self.assertEqual(self.server.requests, [])

    def test_timeout_must_be_finite_and_bounded(self):
        for bad in ("-1", "0", "nan", "inf", "1e9", "121", "abc"):
            with self.subTest(timeout=bad):
                code, _, err = self.run_cli("configs", "list", "--timeout", bad)
                self.assertEqual(code, 2)
                self.assertNotIn("Traceback", err)
        self.assertEqual(self.server.requests, [])

    def test_timeout_bounds_accept_the_edges(self):
        self.server.routes["/api/v1/config/list"] = lambda r: ok({"configs": [], "pageParam": {"total": 0}})
        for good in ("0.1", "20", "120"):
            self.assertEqual(self.run_cli("configs", "list", "--timeout", good)[0], 0, good)

    def test_page_and_page_size_ranges(self):
        for argv in (["configs", "list", "--page", "0"], ["configs", "list", "--page", "10001"],
                     ["configs", "list", "--page-size", "0"], ["configs", "list", "--page-size", "1001"],
                     ["profile", "log", ICCID, "--page", "0"], ["profile", "log", ICCID, "--page-size", "1001"],
                     ["configs", "list", "--page", "x"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_cli(*argv)[0], 2)
        self.assertEqual(self.server.requests, [])
        self.server.routes["/api/v1/config/list"] = lambda r: ok({"configs": [], "pageParam": {"total": 0}})
        self.assertEqual(self.run_cli("configs", "list", "--page", "10000", "--page-size", "1000")[0], 0)
        self.assertEqual(self.run_cli("configs", "list", "--page", "1", "--page-size", "1")[0], 0)


class VersionTests(unittest.TestCase):
    def test_package_version_matches_pyproject(self):
        import re
        from simlessly_cli import __version__
        text = (ROOT / "pyproject.toml").read_text()
        self.assertEqual(re.search(r'^version = "([^"]+)"', text, re.M).group(1), __version__)


class EntryPointTests(CliTestCase):
    def run_module(self, *argv):
        env = {k: v for k, v in os.environ.items() if not k.startswith("SIMLESSLY_")}
        env.update({"PYTHONPATH": str(ROOT / "src"), "SIMLESSLY_NO_KEYCHAIN": "1"})
        return subprocess.run([sys.executable, "-m", "simlessly_cli", *argv], capture_output=True, text=True, env=env, timeout=60)

    def test_python_dash_m(self):
        done = self.run_module("config", "check")
        self.assertEqual(done.returncode, 1)
        self.assertIn("missing", done.stdout)
        done = self.run_module("--version")
        self.assertEqual(done.returncode, 0)
        self.assertIn("simlessly-cli", done.stdout)

    def test_dry_run_exit_code_from_real_process(self):
        done = self.run_module("profile", "delete", ICCID)
        self.assertEqual(done.returncode, 2)
        self.assertIn("Dry run", done.stdout)
        self.assertIn("To send:", done.stdout)
        self.assertEqual(done.stderr, "")

    def test_usage_errors(self):
        self.assertEqual(self.run_module("bogus").returncode, 2)
        self.assertEqual(self.run_module().returncode, 2)
