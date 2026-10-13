"""The portal command group (sessions, fleet, logs, allowlists), against a local mock portal."""

import contextlib
import csv
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import support
from support import AC, EID, MockPortal, envelope, ok
from simlessly_cli import auth, cli, client as api, portal, portal_cli, store
from simlessly_cli.cli import main
from simlessly_cli.client import SimlesslyError
from simlessly_cli.portal import PORTAL_PATHS, PortalClient, md5_hex
from test_store import TTY, Runner, fake_platform

EMAIL = "user@example.test"
PASSWORD = "hunter2-not-a-real-password"
PW_HASH = __import__("hashlib").md5(PASSWORD.encode()).hexdigest()   # computed here, independently of portal.py
TOKEN = "PORTALSESSION-token-do-not-leak-0123456789"
EXPIRED_MESSAGE = "portal session expired or invalid; run: simlessly portal login"
POSIX = os.name == "posix"
SECRETS = (EMAIL, PASSWORD, PW_HASH, TOKEN)


def row(i, **extra):
    r = {"iccid": f"89990000000000{i:05d}", "status": ["AVAILABLE", "DELETED", "ENABLED"][i % 3],
         "configName": "demo-config", "configId": "77", "msisdn": f"+1415555{i:04d}",
         "eid": f"{i:032x}", "imsi": f"0010100000{i:05d}", "acString": AC.replace("ABCDEF", f"{i:06d}"),
         "createTime": 1790812800000 + i * 1000, "updateTime": "2026-10-02T10:00:00Z", "notes": f"note {i}"}
    r.update(extra)
    return r


def bad_session(code="10102"):
    return lambda rec: (200, envelope(None, False, "user token invalid, please login first", code), {})


def paged(rows, total="auto", log=None):
    """A fleet/list route that honours pageParam and requires the session token."""
    def route(rec):
        if rec.headers.get("Simlessly-Token") != TOKEN:
            return bad_session()(rec)
        body = json.loads(rec.body)
        num, size = body["pageParam"]["pageNum"], body["pageParam"]["pageSize"]
        if log is not None:
            log.append(body)
        chunk = rows[(num - 1) * size: num * size]
        obj = {"pageData": chunk, "pageParam": {"pageNum": num, "pageSize": size,
                                               "total": len(rows) if total == "auto" else total}}
        if total is None:
            del obj["pageParam"]["total"]
        return ok(obj)
    return route


class PortalCase(support.CliTestCase):
    def setUp(self):
        self.server = MockPortal()
        self.addCleanup(self.server.close)
        self.tmp = Path(tempfile.mkdtemp(prefix="simlessly-portal-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "conf" / "credentials"
        # No API keys: the portal commands must not need them.
        self.env = {"SIMLESSLY_BASE_URL": self.server.url, "SIMLESSLY_CREDENTIALS_FILE": str(self.path),
                    "SIMLESSLY_NO_KEYCHAIN": "1"}
        self.sleeps = []
        patcher = mock.patch.object(portal_cli, "_pause", self.sleeps.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def signed_in(self, token=TOKEN):
        store.file_store(self.path, "portal-token", token)

    def stored_token(self):
        return store.load_file(self.path).get("portal-token")

    def assertClean(self, *texts):
        for text in texts:
            for secret in SECRETS:
                self.assertNotIn(secret, text)

    def login(self, *argv, stdin=None, **kw):
        return self.run_cli("portal", "login", "--store", "file", *argv, stdin=stdin, **kw)

    def only_request(self):
        self.assertEqual(len(self.server.requests), 1)
        return self.server.requests[0]


# ------------------------------------------------------------------ login

class LoginTests(PortalCase):
    def route_login(self, **obj):
        self.server.routes["/api/v1/user/login"] = lambda rec: ok({"token": TOKEN, "isFirstLogin": False,
                                                                   "isRegister": False, **obj})

    def test_sends_the_exact_body_and_headers_and_stores_the_token(self):
        self.route_login()
        code, out, err = self.login("--email", EMAIL, "--password-stdin", stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual((code, out, err), (0, "signed in; session stored in file\n", ""))
        rec = self.only_request()
        self.assertEqual(rec.problems, [])
        self.assertEqual(rec.path, "/api/v1/user/login")
        self.assertEqual(rec.body, '{"email":"%s","password":"%s","activeToken":"","sys":"rsp"}' % (EMAIL, PW_HASH))
        self.assertEqual(PW_HASH, md5_hex(PASSWORD))
        self.assertRegex(PW_HASH, r"^[0-9a-f]{32}$")
        self.assertNotIn("Simlessly-Token", rec.headers)           # omitted before login
        self.assertEqual(rec.headers["Content-Type"], "application/json")
        for name in ("Simlessly-Timestamp", "Simlessly-RequestID", "Simlessly-TimeZone"):
            self.assertIn(name, rec.headers)
        self.assertEqual(self.stored_token(), TOKEN)
        if POSIX:
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertClean(out, err)
        text = self.path.read_text()
        for secret in (EMAIL, PASSWORD, PW_HASH):
            self.assertNotIn(secret, text)                          # only the token is stored

    def test_hidden_prompt_on_a_terminal(self):
        self.route_login()
        prompts = []
        with mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: prompts.append(prompt) or PASSWORD):
            code, out, err = self.login("--email", EMAIL, stdin=TTY(""))
        self.assertEqual((code, out, err), (0, "signed in; session stored in file\n", ""))
        self.assertEqual(len(prompts), 1)
        self.assertIn(PW_HASH, self.only_request().body)

    def test_email_is_asked_for_on_a_terminal(self):
        self.route_login()
        with mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: PASSWORD):
            code, out, err = self.login(stdin=TTY(EMAIL + "\n"))
        self.assertEqual(code, 0, err)
        self.assertIn('"email":"%s"' % EMAIL, self.only_request().body)
        self.assertClean(out, err.replace("Simlessly e-mail address: ", ""))

    def test_refuses_without_a_terminal_unless_password_stdin(self):
        code, out, err = self.login("--email", EMAIL, stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(code, 2)
        self.assertIn("--password-stdin", err)
        self.assertEqual(self.server.requests, [])
        self.assertClean(out, err)
        code, _, err = self.login("--password-stdin", stdin=io.StringIO(PASSWORD + "\n"))     # no e-mail, no terminal
        self.assertEqual(code, 2)
        self.assertIn("--email", err)
        self.assertEqual(self.server.requests, [])

    def test_password_is_never_read_from_the_environment_or_argv(self):
        self.env["SIMLESSLY_PASSWORD"] = PASSWORD
        code, _, err = self.login("--email", EMAIL, stdin=io.StringIO(""))
        self.assertEqual(code, 2)
        self.assertEqual(self.server.requests, [])
        code, _, err = self.login("--email", EMAIL, "--password", PASSWORD)          # refused, and not echoed back
        self.assertEqual(code, 2)
        self.assertIn("not accepted as an argument", err)
        self.assertNotIn(PASSWORD, err)
        self.assertEqual(self.server.requests, [])

    def test_empty_password_and_bad_email_are_usage_errors(self):
        self.assertEqual(self.login("--email", EMAIL, "--password-stdin", stdin=io.StringIO("\n"))[0], 2)
        code, _, err = self.login("--email", "not-an-address", "--password-stdin", stdin=io.StringIO("x\n"))
        self.assertEqual(code, 2)
        self.assertNotIn("not-an-address", err)
        self.assertEqual(self.server.requests, [])

    def test_first_login_note(self):
        self.route_login(isFirstLogin=True)
        code, out, err = self.login("--email", EMAIL, "--password-stdin", stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(code, 0)
        self.assertEqual(out, "signed in; session stored in file\n")
        self.assertIn("first-login", err)
        self.assertClean(out, err)

    def test_refusal_is_reported_without_leaking_what_the_server_echoes(self):
        self.server.routes["/api/v1/user/login"] = lambda rec: (
            200, envelope(None, False, f"wrong password hash {PW_HASH} for {EMAIL}", "20001"), {})
        code, out, err = self.login("--email", EMAIL, "--password-stdin", stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(code, 1)
        self.assertIn("refused", err)
        self.assertClean(out, err)
        self.assertFalse(self.path.exists())

    def test_login_answer_without_a_token_stores_nothing(self):
        self.server.routes["/api/v1/user/login"] = lambda rec: ok({"isFirstLogin": False})
        code, _, err = self.login("--email", EMAIL, "--password-stdin", stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(code, 1)
        self.assertIn("no readable session token", err)
        self.assertFalse(self.path.exists())

    def test_json_output_has_no_token(self):
        self.route_login()
        code, out, err = self.login("--email", EMAIL, "--password-stdin", "--json", stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(json.loads(out), {"signed_in": True, "stored_in": "file"})
        self.assertClean(out, err)

    def test_other_origins_are_refused_before_any_network_use(self):
        code, _, err = self.login("--email", EMAIL, "--password-stdin", "--base-url", "https://evil.example.com",
                                  stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(code, 1)
        self.assertIn("refused", err)
        self.assertEqual(self.server.requests, [])
        self.assertClean(err)

    def test_keychain_write_keeps_the_token_off_argv(self):
        self.route_login()
        stored = {}

        def handler(cmd, kw):
            if cmd == ["security", "-i"]:
                stored["input"] = kw["input"]
                return (0, "", "")
            if cmd[:2] == ["security", "find-generic-password"]:
                return (0, TOKEN + "\n", "") if stored.get("input") else (44, "", "")
            return (0, "", "")
        runner = Runner(handler)
        with fake_platform("darwin", runner, tools=("security",)):
            code, out, err = self.run_cli("portal", "login", "--email", EMAIL, "--password-stdin",
                                          stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual((code, out), (0, "signed in; session stored in keychain\n"))
        self.assertIn('-a "portal-token" -w "%s"' % TOKEN, runner.calls[0][1]["input"])
        for cmd, _ in runner.calls:
            self.assertNotIn(TOKEN, " ".join(cmd))
        self.assertClean(out, err)

    def test_debug_redacts_the_login_body_headers_and_answer(self):
        self.route_login()
        code, out, err = self.login("--email", EMAIL, "--password-stdin", "--debug", stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(code, 0)
        self.assertIn("> POST " + self.server.url + "/api/v1/user/login", err)
        self.assertIn("> Simlessly-Timestamp:", err)
        self.assertIn("[redacted: login credentials]", err)
        self.assertIn('"token": "[redacted]"', err)
        self.assertClean(out, err)


# ------------------------------------------------------------------ token-set / logout

class TokenAndLogoutTests(PortalCase):
    def test_token_set_from_stdin(self):
        code, out, err = self.run_cli("portal", "token-set", "--store", "file", "--from-stdin", stdin=io.StringIO(TOKEN + "\n"))
        self.assertEqual((code, out, err), (0, "session token stored in file\n", ""))
        self.assertEqual(self.stored_token(), TOKEN)
        self.assertEqual(self.server.requests, [])                  # storing a pasted cookie makes no call
        if POSIX:
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_token_set_hidden_prompt_and_cookie_prefix(self):
        with mock.patch.object(cli.getpass, "getpass", lambda prompt="", stream=None: f"simlessly_token={TOKEN};"):
            code, out, err = self.run_cli("portal", "token-set", "--store", "file", stdin=TTY(""))
        self.assertEqual((code, out), (0, "session token stored in file\n"))
        self.assertEqual(self.stored_token(), TOKEN)
        self.assertClean(out, err)

    def test_token_set_refuses_non_terminal_without_flag_and_bad_values(self):
        code, _, err = self.run_cli("portal", "token-set", "--store", "file", stdin=io.StringIO(TOKEN + "\n"))
        self.assertEqual(code, 2)
        self.assertNotIn(TOKEN, err)
        for bad in ("\n", "abcédef\n"):
            code, out, err = self.run_cli("portal", "token-set", "--store", "file", "--from-stdin", stdin=io.StringIO(bad))
            self.assertEqual(code, 1)
            self.assertNotIn("abc", err)
        self.assertFalse(self.path.exists())

    def test_token_set_warns_when_the_environment_would_win(self):
        self.env["SIMLESSLY_PORTAL_TOKEN"] = "another-token-from-env-9999"
        code, out, err = self.run_cli("portal", "token-set", "--store", "file", "--from-stdin", stdin=io.StringIO(TOKEN + "\n"))
        self.assertEqual(code, 0)
        self.assertIn("SIMLESSLY_PORTAL_TOKEN", err)
        self.assertNotIn("another-token-from-env-9999", err)

    def test_logout_calls_the_portal_with_the_token_then_removes_it(self):
        self.signed_in()
        self.server.routes["/api/v1/user/logout"] = lambda rec: ok(None)
        code, out, err = self.run_cli("portal", "logout", "--store", "file")
        self.assertEqual(code, 0, err)
        self.assertIn("removed the stored session from file", out)
        rec = self.only_request()
        self.assertEqual((rec.path, rec.body, rec.headers["Simlessly-Token"]), ("/api/v1/user/logout", "", TOKEN))
        self.assertEqual((rec.method, rec.query), ("GET", ""))
        self.assertNotIn("Content-Type", rec.headers)
        self.assertEqual(rec.problems, [])
        self.assertIsNone(self.stored_token())
        self.assertClean(out, err)

    def test_logout_is_best_effort_when_the_portal_fails(self):
        self.signed_in()
        self.server.routes["/api/v1/user/logout"] = lambda rec: (500, {"oops": TOKEN}, {})
        code, out, err = self.run_cli("portal", "logout", "--store", "file")
        self.assertEqual(code, 0)
        self.assertIn("did not confirm the logout", err)
        self.assertIsNone(self.stored_token())
        self.assertClean(out, err)

    def test_logout_with_an_already_dead_session_is_quiet(self):
        self.signed_in()
        self.server.routes["/api/v1/user/logout"] = bad_session()
        code, out, err = self.run_cli("portal", "logout")
        self.assertEqual((code, err), (0, ""))
        self.assertIsNone(self.stored_token())                      # found in the file, removed from the file

    def test_logout_without_a_stored_token_makes_no_call(self):
        code, out, err = self.run_cli("portal", "logout", "--store", "file")
        self.assertEqual(code, 0)
        self.assertIn("no stored session", out)
        self.assertEqual(self.server.requests, [])

    def test_logout_notes_an_environment_token(self):
        self.env["SIMLESSLY_PORTAL_TOKEN"] = TOKEN
        self.server.routes["/api/v1/user/logout"] = lambda rec: ok(None)
        code, out, err = self.run_cli("portal", "logout", "--store", "file")
        self.assertEqual(code, 0)
        self.assertIn("SIMLESSLY_PORTAL_TOKEN is set in the environment", err)
        self.assertEqual(len(self.server.requests), 1)
        self.assertClean(out, err)


# ------------------------------------------------------------------ fleet

class FleetTests(PortalCase):
    def setUp(self):
        super().setUp()
        self.signed_in()

    def serve(self, rows, **kw):
        self.log = []
        self.server.routes["/api/v1/fleet/list"] = paged(rows, log=self.log, **kw)

    def test_single_page_body_headers_and_table(self):
        self.serve([row(i) for i in range(1, 4)], total=40)
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual((code, err), (0, ""))
        rec = self.only_request()
        self.assertEqual(rec.problems, [])
        self.assertEqual(rec.headers["Simlessly-Token"], TOKEN)
        self.assertEqual(rec.body, '{"iccid":"","iccidList":"","status":"","configId":"","startTime":"","endTime":"",'
                                   '"groupId":"","recycleStatus":"","acString":"","msisdn":"",'
                                   '"pageParam":{"pageNum":1,"pageSize":50}}')
        for i in range(1, 4):
            self.assertIn(row(i)["iccid"], out)
        self.assertIn("demo-config", out)
        self.assertIn("+14155550001", out)
        self.assertIn("2026-10-01T", out)                           # epoch ms shown as ISO UTC
        self.assertIn("3 profiles shown of 40; use --page, or --all", out)
        # status + one-line meaning, with the existing caveat
        self.assertIn("Status meanings:", out)
        self.assertIn("AVAILABLE", out)
        self.assertIn("not proof the eSIM left the phone", out)
        self.assertIn("removed from the device (the one status reported by the phone itself)", out)
        self.assertNotIn("api key", out.lower())

    def test_masking_in_the_table(self):
        self.serve([row(1)])
        code, out, err = self.run_cli("portal", "fleet")
        r = row(1)
        for hidden in (r["acString"], r["eid"], r["imsi"], "1$rsp-eu.simlessly.com"):
            self.assertNotIn(hidden, out)
        self.assertIn("****" + r["acString"][-4:], out)
        self.assertIn("****" + r["eid"][-4:], out)
        self.assertIn("****" + r["imsi"][-4:], out)
        self.assertEqual(err, "")

    def test_filters_are_mapped_into_the_body(self):
        self.serve([row(1)])
        since_local = str(int(datetime(2026, 10, 1).astimezone().timestamp() * 1000))
        until_local = str(int(datetime(2026, 10, 2, 23, 59, 59, 999000).astimezone().timestamp() * 1000))
        code, out, err = self.run_cli("portal", "fleet", "--iccid", "899900000000", "--status", "AVAILABLE",
                                      "--msisdn", "+14155550001", "--since", "2026-10-01", "--until", "2026-10-02",
                                      "--config", "42", "--page", "3", "--page-size", "7")
        self.assertEqual(code, 0, err)
        body = json.loads(self.only_request().body)
        self.assertEqual(body["iccid"], "899900000000")
        self.assertEqual(body["status"], "AVAILABLE")
        self.assertEqual(body["msisdn"], "+14155550001")
        self.assertEqual(body["configId"], "42")
        self.assertEqual((body["startTime"], body["endTime"]), (since_local, until_local))
        self.assertEqual(body["pageParam"], {"pageNum": 3, "pageSize": 7})
        for key in ("iccidList", "groupId", "recycleStatus", "acString"):
            self.assertEqual(body[key], "")

    def test_iso_times_with_an_offset_are_exact_epoch_ms(self):
        self.serve([])
        self.run_cli("portal", "fleet", "--since", "2026-10-01T00:00:00+00:00", "--until", "2026-10-01T12:00:00+00:00")
        body = json.loads(self.only_request().body)
        start = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp() * 1000)
        self.assertEqual((body["startTime"], body["endTime"]), (str(start), str(start + 12 * 3600 * 1000)))

    def test_config_name_is_resolved_with_one_lookup(self):
        self.serve([row(1)])
        lookups = []
        def names(rec):
            lookups.append((rec.method, rec.query, rec.body, rec.headers.get("Simlessly-Token")))
            return ok([{"configName": "other", "configId": "78"}, {"configName": "Demo-Config", "configId": "77"}])
        self.server.routes["/api/v1/config/name/query"] = names
        code, out, err = self.run_cli("portal", "fleet", "--config", "demo-config")
        self.assertEqual(code, 0, err)
        self.assertEqual(lookups, [("GET", "filterDemo=false", "", TOKEN)])
        self.assertEqual(json.loads(self.server.requests[-1].body)["configId"], "77")

    def test_config_name_not_found_lists_the_known_names(self):
        self.serve([])
        self.server.routes["/api/v1/config/name/query"] = lambda rec: ok({"list": [{"name": "a", "id": 1}, {"name": "b", "id": 2}]})
        code, out, err = self.run_cli("portal", "fleet", "--config", "nope")
        self.assertEqual(code, 2)
        self.assertIn("portal knows: a, b", err)
        self.assertEqual([r.path for r in self.server.requests], ["/api/v1/config/name/query"])

    def test_config_list_in_an_unknown_shape_says_to_use_the_id(self):
        self.serve([])
        self.server.routes["/api/v1/config/name/query"] = lambda rec: ok([1, 2, None])
        code, out, err = self.run_cli("portal", "fleet", "--config", "demo-config")
        self.assertEqual(code, 1)
        self.assertIn("configId", err)

    def lookup_with(self, obj):
        self.server.requests.clear()
        self.serve([row(1)])
        self.server.routes["/api/v1/config/name/query"] = lambda rec: ok(obj)
        code, out, err = self.run_cli("portal", "fleet", "--config", "Demo-Config")
        return code, err, [r for r in self.server.requests if r.path == "/api/v1/fleet/list"]

    def test_config_name_lookup_accepts_the_likely_item_shapes(self):
        shapes = {
            "label/value": [{"label": "other", "value": "9"}, {"label": "demo-config", "value": "77"}],
            "name/id": [{"name": "other", "id": 9}, {"name": "DEMO-CONFIG", "id": 77}],
            "configName/configId": {"list": [{"configName": "demo-config", "configId": "77"}]},
            "plain strings": ["other", "demo-config"],
            "match on any string field": [{"label": "x", "value": "77", "desc": "demo-config"}],
        }
        for label, obj in shapes.items():
            with self.subTest(label):
                code, err, fleet = self.lookup_with(obj)
                self.assertEqual(code, 0, err)
                want = "demo-config" if label == "plain strings" else "77"
                self.assertEqual(json.loads(fleet[0].body)["configId"], want)

    def test_config_name_ambiguous_or_without_id_is_refused(self):
        code, err, fleet = self.lookup_with([{"name": "demo-config", "id": 1}, {"name": "Demo-Config", "id": 2}])
        self.assertEqual((code, fleet), (2, []))
        self.assertIn("several configurations", err)
        code, err, fleet = self.lookup_with([{"name": "demo-config"}, {"name": "x", "id": 5}])
        self.assertEqual((code, fleet), (1, []))

    def test_numeric_and_uuid_config_skip_the_lookup(self):
        self.serve([])
        for value in ("77", "0123e4567-e89b-12d3-a456-426614174000"[1:]):
            self.run_cli("portal", "fleet", "--config", value)
        self.assertEqual([r.path for r in self.server.requests], ["/api/v1/fleet/list"] * 2)

    def test_bad_filters_fail_before_any_call(self):
        for argv in (["--iccid", "12ab"], ["--msisdn", "abc"], ["--since", "yesterday"], ["--status", "x;y"],
                     ["--since", "2026-10-03", "--until", "2026-10-01"], ["--all", "--page", "2"],
                     ["--page-size", "500"], ["--page", "0"]):
            code, _, err = self.run_cli("portal", "fleet", *argv)
            self.assertEqual(code, 2, argv)
        self.assertEqual(self.server.requests, [])

    def test_all_walks_every_page_with_a_pause_and_a_total(self):
        self.serve([row(i) for i in range(1, 8)])
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "3")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual([b["pageParam"]["pageNum"] for b in self.log], [1, 2, 3])
        self.assertEqual(self.sleeps, [0.5, 0.5])                    # between pages, not before the first
        self.assertIn("7 profiles shown of 7 (3 pages fetched).", out)
        for i in range(1, 8):
            self.assertIn(row(i)["iccid"], out)

    def test_all_stops_at_the_hard_cap(self):
        self.assertEqual((portal_cli.MAX_PAGES, portal_cli.PAGE_PAUSE), (100, 0.5))
        self.serve([row(i) for i in range(1, 40)], total=5000)
        with mock.patch.object(portal_cli, "MAX_PAGES", 3):
            code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "2")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.log), 3)
        self.assertIn("stopped at the 3-page cap", err)
        self.assertIn("6 profiles shown of 5000 (3 pages fetched)", out)
        self.assertEqual(len(self.sleeps), 2)

    def test_all_without_a_reported_total_stops_on_an_empty_page_and_says_so(self):
        self.serve([row(i) for i in range(1, 6)], total=None)
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "2")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.log), 4)                           # a short page is not taken as the last one
        self.assertIn("5 profiles shown (4 pages fetched)", out)
        self.assertIn("completeness could not be checked", err)

    def test_all_stops_if_the_portal_ignores_the_page_number(self):
        rows = [row(i) for i in range(1, 4)]
        self.server.routes["/api/v1/fleet/list"] = lambda rec: ok({"pageData": rows, "total": 99})
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "3")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.server.requests), 2)
        self.assertIn("same rows again", err)
        self.assertIn("3 profiles shown", out)

    def test_all_json_has_the_raw_shape_plus_paging_facts(self):
        self.serve([row(i) for i in range(1, 6)])
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "2", "--json")
        data = json.loads(out)
        self.assertEqual((data["pagesFetched"], data["truncated"], len(data["pageData"])), (3, False, 5))
        self.assertEqual((data["complete"], data["stopReason"]), (True, "total-reached"))
        self.assertEqual(data["pageParam"]["total"], 5)

    def test_json_is_masked_and_keeps_unknown_fields(self):
        self.serve([row(1, extra={"x": 1}), {"iccid": "8999000000000009999"}])
        code, out, err = self.run_cli("portal", "fleet", "--json")
        data = json.loads(out)
        first = data["pageData"][0]
        self.assertEqual(first["extra"], {"x": 1})
        self.assertEqual(first["acString"], "****" + row(1)["acString"][-4:])
        self.assertEqual(first["eid"], "****" + row(1)["eid"][-4:])
        self.assertEqual(first["notes"], "note 1")
        self.assertNotIn(row(1)["acString"], out)
        self.assertEqual(data["pageData"][1], {"iccid": "8999000000000009999"})

    def test_rows_with_missing_fields_still_render(self):
        self.serve([{"iccid": "8999000000000000001"}, {"iccid": "8999000000000000002", "status": None, "eid": None,
                                                        "configId": "9", "createTime": "not a time"}])
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("8999000000000000002", out)
        self.assertIn("not a time", out)

    def test_reveal_ac_shows_only_the_activation_codes(self):
        self.serve([row(1)])
        code, out, err = self.run_cli("portal", "fleet", "--reveal-ac")
        self.assertEqual(code, 0)
        self.assertIn(row(1)["acString"], out)
        self.assertNotIn(row(1)["eid"], out)
        self.assertNotIn(row(1)["imsi"], out)
        self.assertIn("bearer secrets", err)
        code, out, err = self.run_cli("portal", "fleet", "--reveal-ac", "--json")
        data = json.loads(out)["pageData"][0]
        self.assertEqual(data["acString"], row(1)["acString"])
        self.assertEqual(data["eid"], "****" + row(1)["eid"][-4:])

    def test_csv_is_private_masked_and_formula_safe(self):
        self.serve([row(1), row(2, configName='=HYPERLINK("http://x")'), row(3, msisdn="+14155559999")])
        target = self.tmp / "out.csv"
        target.write_text("old contents\n")
        if POSIX:
            os.chmod(target, 0o644)
        code, out, err = self.run_cli("portal", "fleet", "--csv", str(target))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("wrote 3 profiles", out)
        self.assertNotIn("8999", out)                                # the table is not printed alongside
        if POSIX:
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        text = target.read_text()
        self.assertNotIn("old contents", text)
        for hidden in (row(1)["acString"], row(1)["eid"], row(1)["imsi"], TOKEN):
            self.assertNotIn(hidden, text)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0], portal_cli.FLEET_COLUMNS + ["status meaning"])
        self.assertEqual(rows[1][0], row(1)["iccid"])
        self.assertEqual(rows[1][6], "****" + row(1)["acString"][-4:])
        self.assertTrue(rows[2][2].startswith("'="))                  # not a live formula
        self.assertEqual(rows[3][3], "+14155559999")                  # a plain phone number is left alone
        self.assertIn("not proof the eSIM left the phone", rows[3][-1])      # row 3 is AVAILABLE

    def test_csv_with_reveal_ac_has_codes_and_warns(self):
        self.serve([row(1)])
        target = self.tmp / "ac.csv"
        code, out, err = self.run_cli("portal", "fleet", "--csv", str(target), "--reveal-ac")
        self.assertEqual(code, 0)
        self.assertIn(row(1)["acString"], target.read_text())
        self.assertNotIn(row(1)["eid"], target.read_text())
        self.assertIn("bearer secrets", err)
        if POSIX:
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)

    def test_csv_to_a_bad_path_is_an_error(self):
        self.serve([row(1)])
        code, out, err = self.run_cli("portal", "fleet", "--csv", str(self.tmp / "no-such-dir" / "x.csv"))
        self.assertEqual(code, 1)
        self.assertIn("could not write", err)

    def test_nothing_secret_in_debug(self):
        self.serve([row(1)])
        code, out, err = self.run_cli("portal", "fleet", "--debug")
        self.assertEqual(code, 0)
        self.assertIn("> Simlessly-Token: [redacted]", err)
        self.assertClean(out, err)
        self.assertNotIn(row(1)["acString"], err)
        self.assertNotIn(row(1)["eid"], err)

    def test_unexpected_answer_shape(self):
        self.server.routes["/api/v1/fleet/list"] = lambda rec: ok({"rows": []})
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 1)
        self.assertIn("unexpected answer shape", err)

    def test_empty_result(self):
        self.serve([])
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 0)
        self.assertIn("No profiles found.", out)


# ------------------------------------------------------------------ session handling

class SessionTests(PortalCase):
    def test_expired_codes_print_the_login_hint_and_never_retry(self):
        self.signed_in()
        for code_ in ("10102", "10103", "10206", " 10102 "):
            self.server.requests.clear()
            self.server.routes["/api/v1/fleet/list"] = bad_session(code_)
            code, out, err = self.run_cli("portal", "fleet")
            self.assertEqual((code, out), (1, ""), code_)
            self.assertEqual(err, "error: " + EXPIRED_MESSAGE + "\n")
            self.assertEqual([r.path for r in self.server.requests], ["/api/v1/fleet/list"])   # no login, no retry
            self.assertEqual(self.stored_token(), TOKEN)               # the token is not touched automatically

    def test_expired_in_the_middle_of_all(self):
        self.signed_in()
        good = paged([row(i) for i in range(1, 10)])
        calls = []
        def route(rec):
            calls.append(1)
            return good(rec) if len(calls) == 1 else bad_session("10103")(rec)
        self.server.routes["/api/v1/fleet/list"] = route
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "2")
        self.assertEqual((code, out), (1, ""))
        self.assertIn(EXPIRED_MESSAGE, err)
        self.assertEqual(len(calls), 2)

    def test_expired_on_logs_and_config_lookup(self):
        self.signed_in()
        self.server.routes["/api/v1/log/profile/list"] = bad_session("10206")
        self.server.routes["/api/v1/config/name/query"] = bad_session("10102")
        for argv in (["logs"], ["fleet", "--config", "demo"]):
            code, out, err = self.run_cli("portal", *argv)
            self.assertEqual((code, out, err), (1, "", "error: " + EXPIRED_MESSAGE + "\n"))

    def test_no_stored_session_makes_no_call(self):
        for argv in (["fleet"], ["logs"]):
            code, out, err = self.run_cli("portal", *argv)
            self.assertEqual(code, 1)
            self.assertIn("simlessly portal login", err)
        self.assertEqual(self.server.requests, [])

    def test_environment_token_is_used(self):
        self.env["SIMLESSLY_PORTAL_TOKEN"] = TOKEN
        self.server.routes["/api/v1/fleet/list"] = paged([row(1)])
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 0, err)

    def test_other_api_failures_are_ordinary_errors(self):
        self.signed_in()
        self.server.routes["/api/v1/fleet/list"] = lambda rec: (200, envelope(None, False, f"boom {TOKEN} {AC}", "50000"), {})
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 1)
        self.assertIn("boom", err)
        self.assertNotIn("expired", err)
        self.assertClean(err)
        self.assertNotIn(AC, err)
        self.server.routes["/api/v1/fleet/list"] = lambda rec: (503, b"down", {})
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 1)                                      # a read command never exits 3
        self.assertNotIn("OUTCOME UNKNOWN", err)

    def test_redirect_and_oversize_answers_are_refused(self):
        self.signed_in()
        self.server.routes["/api/v1/fleet/list"] = lambda rec: (302, b"", {"Location": "https://evil.example.com/x"})
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 1)
        self.assertIn("redirect", err)
        self.server.routes["/api/v1/fleet/list"] = lambda rec: (200, b"x" * ((1 << 20) + 10), {})
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 1)
        self.assertIn("1 MiB", err)

    def test_base_url_must_stay_pinned(self):
        self.signed_in()
        code, _, err = self.run_cli("portal", "fleet", "--base-url", "https://evil.example.com")
        self.assertEqual(code, 1)
        self.assertEqual(self.server.requests, [])
        self.assertNotIn(TOKEN, err)


# ------------------------------------------------------------------ logs

class LogsTests(PortalCase):
    def test_logs_list(self):
        self.signed_in()
        seen = []
        def route(rec):
            seen.append(rec)
            return ok({"pageData": [{"createTime": "2026-10-02 10:00:00", "iccid": "8999000000000000001", "status": "DELETED",
                                     "reason": "", "operator": "device", "eid": EID}],
                       "pageParam": {"total": 9}})
        self.server.routes["/api/v1/log/profile/list"] = route
        code, out, err = self.run_cli("portal", "logs", "--iccid", "8999000000000000001", "--page", "2", "--page-size", "5")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(seen[0].body, '{"iccid":"8999000000000000001","status":"","startTime":"","endTime":"",'
                                      '"pageParam":{"pageNum":2,"pageSize":5}}')
        self.assertEqual(seen[0].method, "POST")
        self.assertEqual(seen[0].headers["Simlessly-Token"], TOKEN)
        self.assertIn("DELETED", out)
        self.assertIn("1 entries shown of 9", out)
        self.assertNotIn(EID, out)
        self.assertIn("****" + EID[-4:], out)
        code, out, err = self.run_cli("portal", "logs")
        self.assertEqual(json.loads(seen[1].body)["iccid"], "")

    def test_logs_json_is_masked(self):
        self.signed_in()
        self.server.routes["/api/v1/log/profile/list"] = lambda rec: ok({"pageData": [{"eid": EID, "iccid": "1"}]})
        code, out, err = self.run_cli("portal", "logs", "--json")
        self.assertNotIn(EID, out)
        self.assertEqual(json.loads(out)["pageData"][0]["eid"], "****" + EID[-4:])


# ------------------------------------------------------------------ allowlist

class AllowlistTests(PortalCase):
    # path -> method, the methods from the last observed portal (see support.PORTAL_*_PATHS)
    SESSION = {p: support.OBSERVED_PORTAL_METHODS[p] for p in support.PORTAL_SESSION_PATHS}
    READ = {p: support.OBSERVED_PORTAL_METHODS[p] for p in support.PORTAL_READ_PATHS}
    WRITE = {p: support.OBSERVED_PORTAL_METHODS[p] for p in support.PORTAL_WRITE_PATHS}
    # on the website but not implemented (billing, other people's access, secrets, operator calls)
    NOT_IMPLEMENTED = ["/api/v1/order/create", "/api/v1/order/paid", "/api/v1/order/cancel", "/api/v1/plan/cancelSubscription",
                       "/api/v1/enterprise/add", "/api/v1/enterprise/switch", "/api/v1/developer/keys",
                       "/api/v1/developer/keys/init", "/api/v1/developer/notificationURL/update", "/api/v1/user/add",
                       "/api/v1/user/delete", "/api/v1/user/changePassword", "/api/v1/role/save", "/api/v1/block/add",
                       "/api/v1/block/remove", "/api/v1/campaign/create", "/api/v1/campaign/change-status",
                       "/api/v1/campaign/resource/delete", "/api/v1/campaign/resource/unlock",
                       "/api/v1/campaign/resource/import", "/api/v1/event/profile/push", "/api/v1/config/add",
                       "/api/v1/config/update", "/api/v1/config/delete", "/api/v1/group/delete",
                       "/api/v1/fleet/single-generate", "/api/v1/admin/order/create", "/api/v1/admin/client/delete",
                       "/api/v1/fleet/downloadPgpKey", "/api/v1/report/config/export"]

    def test_exact_portal_allowlist(self):
        self.assertEqual(PORTAL_PATHS, frozenset({*self.SESSION, *self.READ, *self.WRITE}))
        self.assertEqual(portal.READ_PATHS, frozenset(self.READ))
        self.assertEqual(portal.WRITE_PATHS, frozenset(self.WRITE))

    def test_methods_and_transports_match_the_last_observed_portal(self):
        for path in support.PORTAL_ALLOWED_PATHS:
            seen = support.OBSERVED_PORTAL.get(path)
            self.assertIsNotNone(seen, f"{path} is not in api-snapshot/portal.json")
            self.assertEqual(portal.PORTAL_METHODS[path], seen["method"], path)
            expected = "multipart" if path in portal.MULTIPART_PATHS else ("query" if seen["method"] == "GET" else "json")
            self.assertEqual(seen["transport"], expected, path)

    def test_fixed_method_per_path(self):
        self.assertEqual(dict(portal.SESSION_METHODS), self.SESSION)
        self.assertEqual(dict(portal.READ_METHODS), self.READ)
        self.assertEqual(dict(portal.WRITE_METHODS), self.WRITE)
        self.assertEqual(dict(portal.PORTAL_METHODS), {**self.SESSION, **self.READ, **self.WRITE})
        for mapping in (portal.PORTAL_METHODS, portal.READ_METHODS, portal.WRITE_METHODS):
            with self.assertRaises(TypeError):
                mapping["/api/v1/block/add"] = "POST"                              # read-only mappings
        self.assertEqual(self.server.METHODS, dict(portal.PORTAL_METHODS))       # the mock restates the same facts

    def test_the_read_and_write_maps_do_not_overlap(self):
        self.assertEqual(portal.READ_PATHS & portal.WRITE_PATHS, set())
        self.assertEqual((portal.READ_PATHS | portal.WRITE_PATHS) & set(self.SESSION), set())

    def test_every_allowed_path_is_sent_with_its_method_and_the_mock_rejects_the_wrong_one(self):
        client = PortalClient(self.server.url, TOKEN, timezone="UTC")
        for path, method in {**self.READ, **self.SESSION}.items():
            if path in portal.BINARY_READ_PATHS:
                continue
            self.server.routes[path] = lambda rec: ok({"seen": rec.method})
            call = client.session if path in self.SESSION else client.read
            self.assertEqual(call(path, {"a": "b c&d=é"}), {"seen": method}, path)
            self.assertEqual(self.server.requests[-1].method, method, path)
            self.assertEqual(self.server.requests[-1].problems, [], path)
        for path, method in self.WRITE.items():
            if path in portal.MULTIPART_PATHS:
                continue
            self.server.routes[path] = lambda rec: ok({"seen": rec.method})
            self.assertEqual(client.write(path, {"a": "b"}), {"seen": method}, path)
            self.assertEqual(self.server.requests[-1].problems, [], path)

    def test_a_wrong_method_is_exactly_the_live_failure_and_is_reported_clearly(self):
        # Simulate a regression to POST: the mock answers like the live portal (HTTP 200, 10008).
        client = PortalClient(self.server.url, TOKEN, timezone="UTC")
        status, raw = client._send(self.server.url + "/api/v1/config/name/query", {
            "Simlessly-Timestamp": auth.new_timestamp(), "Simlessly-RequestID": auth.new_request_id(),
            "Simlessly-TimeZone": "UTC", "Content-Type": "application/json"}, b"{}", "POST")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {"obj": None, "success": False, "code": "10008",
                                           "msg": "request method not support[Request method 'POST' not supported]"})
        with self.assertRaises(SimlesslyError) as cm:
            client._open_envelope(status, raw)
        self.assertEqual(cm.exception.code, "10008")

    def test_code_10008_names_the_path_and_never_the_token(self):
        self.signed_in()
        self.server.routes["/api/v1/fleet/list"] = lambda rec: (
            200, envelope(None, False, f"request method not support[{TOKEN}]", "10008"), {})
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("/api/v1/fleet/list", err)
        self.assertIn("10008", err)
        self.assertIn("may have changed", err)
        self.assertNotIn("nofficial", err)
        self.assertClean(err)

    def test_get_query_is_url_encoded_without_a_body(self):
        self.assertEqual(portal.encode_query({"filterDemo": False}), "filterDemo=false")
        self.assertEqual(portal.encode_query({"a": True, "b": "x y&z=1", "c": None, "d": 3}), "a=true&b=x+y%26z%3D1&d=3")
        self.assertEqual(portal.encode_query(None), "")

    def test_unknown_paths_raise_before_any_network_io(self):
        client = PortalClient(self.server.url, TOKEN, timezone="UTC")
        junk = ["/api/v1/fleet/list/", "/api/v1/fleet/../fleet/delete", "/api/v1/profile/delete",
                "/api/v1/config/name/query?x=1", "/api/v1/user/logout#", "/api/v2/ac/generate",
                "/gsma/rsp2/es2plus/confirmOrder", "", "fleet/list"]
        for path in junk + self.NOT_IMPLEMENTED:
            for call in (client.session, client.read, client.read_bytes, client.write):
                with self.assertRaises(SimlesslyError) as cm:
                    call(path, {})
                self.assertEqual(cm.exception.kind, "config", path)
            with self.assertRaises(SimlesslyError):
                client.write_multipart(path, [], "f.gpg", b"x")
        self.assertEqual(self.server.requests, [])

    def test_a_read_call_can_never_reach_a_state_changing_path(self):
        client = PortalClient(self.server.url, TOKEN, timezone="UTC")
        for path in self.WRITE:
            for call in (client.read, client.read_bytes, client.session):
                with self.assertRaises(SimlesslyError) as cm:
                    call(path, {"ids": [1]})
                self.assertEqual(cm.exception.kind, "config", path)
                self.assertIn("refusing to call portal path", str(cm.exception))
        for path in list(self.READ) + list(self.SESSION):
            with self.assertRaises(SimlesslyError):
                client.write(path, {})
            with self.assertRaises(SimlesslyError):
                client.write_multipart(path, [], "f.gpg", b"x")
        # the two special transports cannot be used the wrong way round
        with self.assertRaises(SimlesslyError):
            client.read("/api/v1/fleet/qrcode", {})
        with self.assertRaises(SimlesslyError):
            client.write("/api/v1/fleet/generateAc", {})
        with self.assertRaises(SimlesslyError):
            client.write_multipart("/api/v1/fleet/delete", [], "f.gpg", b"x")
        self.assertEqual(self.server.requests, [])

    def test_the_two_allowlists_do_not_overlap(self):
        self.assertEqual(PORTAL_PATHS & api.ALLOWED_PATHS, set())
        for path in PORTAL_PATHS:
            with self.assertRaises(SimlesslyError):
                api.build_url(self.server.url, path)                 # the signed client cannot reach portal paths
        for path in api.ALLOWED_PATHS:
            with self.assertRaises(SimlesslyError):
                portal.build_portal_url(self.server.url, path)

    def test_read_commands_never_reach_a_state_changing_path(self):
        self.signed_in()
        self.server.routes["/api/v1/fleet/list"] = paged([row(1)])
        self.run_cli("portal", "fleet")
        self.run_cli("portal", "logs")
        self.run_cli("portal", "logout", "--store", "file")
        self.assertTrue(self.server.requests)
        for rec in self.server.requests:
            self.assertIn(rec.path, PORTAL_PATHS)
            self.assertNotIn(rec.path, portal.WRITE_PATHS)
        for word in ("destroy", "block-add", "order-create", "switch"):
            code, out, err = self.run_cli("portal", word)
            self.assertEqual(code, 2)                                # not a command


class EndpointDataTests(unittest.TestCase):
    """portal_endpoints.json is loaded fail-closed: anything irregular stops the import."""

    GOOD = {"session": {portal.PATH_LOGIN: "POST"}, "read": {"/api/v1/a/get": "GET"},
            "write": {"/api/v1/a/put": "POST"}, "multipart": ["/api/v1/a/put"]}

    def load(self, data):
        return portal._load_endpoints(data if isinstance(data, str) else json.dumps(data))

    def test_good_data_loads(self):
        groups, multipart = self.load(self.GOOD)
        self.assertEqual(groups["read"], {"/api/v1/a/get": "GET"})
        self.assertEqual(multipart, frozenset({"/api/v1/a/put"}))

    def test_the_packaged_file_is_loaded_and_is_json_next_to_the_module(self):
        path = Path(portal.__file__).with_name("portal_endpoints.json")
        groups, multipart = self.load(path.read_text(encoding="utf-8"))
        self.assertEqual(groups["read"], dict(portal.READ_METHODS))
        self.assertEqual(multipart, portal.MULTIPART_PATHS)

    def test_irregular_data_is_refused(self):
        def bad(**change):
            data = json.loads(json.dumps(self.GOOD))
            data.update(change)
            return data
        cases = {
            "not json": "{",
            "a list": "[]",
            "missing group": {k: v for k, v in self.GOOD.items() if k != "write"},
            "extra key": bad(extra={}),
            "empty group": bad(read={}),
            "unknown method": bad(read={"/api/v1/a/get": "PUT"}),
            "lower-case method": bad(read={"/api/v1/a/get": "get"}),
            "path outside /api/vN/": bad(read={"/other/get": "GET"}),
            "path with a query": bad(read={"/api/v1/a/get?x=1": "GET"}),
            "path with a dot segment": bad(read={"/api/v1/a/../get": "GET"}),
            "same path in two groups": bad(read={"/api/v1/a/put": "POST"}),
            "multipart path not in write": bad(multipart=["/api/v1/a/get"]),
            "multipart path that is a GET": bad(write={"/api/v1/a/put": "GET"}),
            "write path that is a GET": bad(write={"/api/v1/a/put": "POST", "/api/v1/a/del": "GET"}),
            "login as GET": bad(session={portal.PATH_LOGIN: "GET"}),
            "login missing from the session group": bad(session={"/api/v1/a/logout": "GET"}),
            "login in the read group": bad(session={"/api/v1/a/logout": "GET"}, read={portal.PATH_LOGIN: "POST"}),
            "multipart not a list": bad(multipart="/api/v1/a/put"),
        }
        for label, data in cases.items():
            with self.assertRaises(RuntimeError, msg=label):
                self.load(data)


class ConfigIntegrationTests(PortalCase):
    def test_portal_token_is_a_known_optional_setting(self):
        env = {**self.env, "SIMLESSLY_ACCESS_KEY": support.ACCESS, "SIMLESSLY_SECRET_KEY": support.SECRET}
        code, out, err = self.run_cli("config", "check", env=env)
        self.assertEqual(code, 0)                                    # not required for "Ready."
        self.assertIn("portal-token", out)
        self.assertIn("SIMLESSLY_PORTAL_TOKEN", out)
        self.assertIn("Ready.", out)
        self.signed_in()
        code, out, err = self.run_cli("config", "check", env=env)
        self.assertIn("set (file", out)
        self.assertNotIn(TOKEN, out)
        self.assertEqual(json.loads(self.run_cli("config", "check", "--json", env=env)[1])["settings"]["portal-token"][:8], "set (fil")

    def test_config_set_portal_token_stores_it_like_the_keys(self):
        code, out, err = self.run_cli("config", "set", "portal-token", "--store", "file", "--from-stdin", stdin=io.StringIO(TOKEN + "\n"))
        self.assertEqual((code, out), (0, "stored portal-token in file\n"))
        self.assertEqual(self.stored_token(), TOKEN)
        code, out, err = self.run_cli("config", "set", "portal-token", "--store", "file", "--from-stdin", stdin=io.StringIO("tokén\n"))
        self.assertEqual(code, 1)                                    # ASCII only: it travels in a header

    def test_a_refused_credentials_file_is_a_hard_error_for_the_token(self):
        if not POSIX:
            self.skipTest("POSIX permission check")
        self.signed_in()
        os.chmod(self.path, 0o644)
        code, out, err = self.run_cli("portal", "fleet")
        self.assertEqual(code, 1)
        self.assertEqual(self.server.requests, [])
        self.assertNotIn(TOKEN, err)


class TimezoneTests(unittest.TestCase):
    def test_zone_names(self):
        self.assertEqual(portal.local_timezone({"TZ": "America/Los_Angeles"}), "America/Los_Angeles")
        self.assertEqual(portal.local_timezone({"TZ": ":Europe/Berlin"}), "Europe/Berlin")
        self.assertRegex(portal.local_timezone({"TZ": "PST8PDT garbage; rm -rf"}), r"^(UTC|GMT|[A-Za-z]+(/[A-Za-z0-9_+\-]+)+)$")
        self.assertRegex(portal.local_timezone({}), r"^(UTC|GMT|[A-Za-z]+(/[A-Za-z0-9_+\-]+)+)$")


if __name__ == "__main__":
    unittest.main()
