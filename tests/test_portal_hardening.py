"""Portal commands: completeness reporting, logout of shadowed copies, no secret echoes, IMSI masking."""

import io
import json
import os
import unittest
from unittest import mock

import support
from support import envelope, ok
from simlessly_cli import cli, output, portal_cli, store
from simlessly_cli.output import Redactor
from test_portal import EMAIL, PASSWORD, PW_HASH, TOKEN, PortalCase, paged, row
from test_store import TTY, Runner, fake_platform

OTHER_TOKEN = "SHADOWED-portal-token-do-not-leak-98765"


class FleetServing(PortalCase):
    def setUp(self):
        super().setUp()
        self.signed_in()
        self.log = []

    def serve(self, rows, **kw):
        self.server.routes["/api/v1/fleet/list"] = paged(rows, log=self.log, **kw)

    def serve_capped(self, rows, cap, with_total=False):
        """A portal that silently serves at most `cap` rows per page whatever pageSize was asked for."""
        def route(rec):
            body = json.loads(rec.body)
            num = body["pageParam"]["pageNum"]
            self.log.append(body)
            obj = {"pageData": rows[(num - 1) * cap: num * cap]}
            if with_total:
                obj["total"] = len(rows)
            return ok(obj)
        self.server.routes["/api/v1/fleet/list"] = route


class CompletenessTests(FleetServing):
    def test_a_silently_capped_page_size_without_a_total_is_not_taken_for_the_last_page(self):
        self.serve_capped([row(i) for i in range(1, 251)], cap=100)
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "200", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(data["pageData"]), 250)
        self.assertEqual([b["pageParam"]["pageNum"] for b in self.log], [1, 2, 3, 4])   # ends on the empty page
        self.assertEqual((data["pagesFetched"], data["truncated"], data["stopReason"]), (4, False, "empty-page"))
        self.assertIsNone(data["complete"])                                           # unknown, not "true"
        self.assertIn("no total", err)
        self.assertIn("completeness could not be checked", err)

    def test_a_known_total_adds_no_extra_request_and_no_note(self):
        self.serve_capped([row(i) for i in range(1, 251)], cap=100, with_total=True)
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "200", "--json")
        data = json.loads(out)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual((len(data["pageData"]), data["pagesFetched"], data["complete"], data["truncated"],
                          data["stopReason"]), (250, 3, True, False, "total-reached"))

    def test_repeated_rows_are_reported_as_incomplete_in_the_data(self):
        rows = [row(i) for i in range(1, 6)]
        self.server.routes["/api/v1/fleet/list"] = lambda rec: ok({"pageData": rows, "total": 10})
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "5", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual((data["truncated"], data["complete"], data["stopReason"]), (True, False, "repeated-rows"))
        self.assertIn("same rows again", err)
        self.assertIn("not complete", err)

    def test_an_empty_page_before_the_total_is_incomplete(self):
        self.serve([row(i) for i in range(1, 6)], total=10)
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "5", "--json")
        data = json.loads(out)
        self.assertEqual((code, len(data["pageData"])), (0, 5))
        self.assertEqual((data["truncated"], data["complete"], data["stopReason"]), (True, False, "short-of-total"))
        self.assertIn("not complete", err)

    def test_strict_exits_nonzero_for_a_known_incomplete_list_only(self):
        self.serve([row(i) for i in range(1, 6)], total=10)
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "5", "--strict")
        self.assertEqual(code, 1)
        self.assertIn("--strict", err)
        self.assertIn(row(1)["iccid"], out)                                  # the rows are still printed
        self.log.clear()
        self.serve([row(i) for i in range(1, 6)])                            # complete
        self.assertEqual(self.run_cli("portal", "fleet", "--all", "--page-size", "5", "--strict")[0], 0)
        self.serve([row(i) for i in range(1, 6)], total=None)                # unknown is not "known incomplete"
        self.assertEqual(self.run_cli("portal", "fleet", "--all", "--page-size", "5", "--strict")[0], 0)

    def test_the_cap_is_truncated_and_incomplete(self):
        self.serve([row(i) for i in range(1, 40)], total=5000)
        with mock.patch.object(portal_cli, "MAX_PAGES", 2):
            code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "2", "--json", "--strict")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual((data["truncated"], data["complete"], data["stopReason"]), (True, False, "page-cap"))

    def test_csv_summary_carries_the_completeness_facts(self):
        self.serve([row(i) for i in range(1, 6)], total=10)
        csv_path = self.tmp / "out.csv"
        code, out, err = self.run_cli("portal", "fleet", "--all", "--page-size", "5", "--csv", str(csv_path), "--json")
        data = json.loads(out)
        self.assertEqual((data["truncated"], data["complete"], data["stopReason"]), (True, False, "short-of-total"))

    def test_single_page_output_has_no_completeness_fields(self):
        self.serve([row(i) for i in range(1, 6)])
        data = json.loads(self.run_cli("portal", "fleet", "--json")[1])
        for key in ("truncated", "complete", "stopReason"):
            self.assertNotIn(key, data)


class LogoutShadowTests(PortalCase):
    def setUp(self):
        super().setUp()
        del self.env["SIMLESSLY_NO_KEYCHAIN"]
        self.kc = {"value": TOKEN}
        self.logouts = []
        self.server.routes["/api/v1/user/logout"] = lambda rec: (self.logouts.append(rec.headers["Simlessly-Token"]),
                                                                  ok(None))[1]

    def handler(self, cmd, kw):
        if cmd[:2] == ["security", "delete-generic-password"]:
            had, self.kc["value"] = self.kc["value"], None
            return (0, "", "") if had else (44, "", "")
        return (0, "", "")

    def logout(self, *argv):
        runner = Runner(self.handler)
        with fake_platform("darwin", runner, tools=("security",)):
            return self.run_cli("portal", "logout", *argv, keychain=lambda name: self.kc["value"])

    def test_logout_removes_and_ends_a_shadowed_second_copy(self):
        store.file_store(self.path, "portal-token", OTHER_TOKEN)
        code, out, err = self.logout()
        self.assertEqual(code, 0, err)
        self.assertIn("removed the stored session from keychain", out)
        self.assertIn("also removed a second stored session from file", out)
        self.assertEqual(self.logouts, [TOKEN, OTHER_TOKEN])                  # both portal sessions were ended
        self.assertIsNone(self.kc["value"])
        self.assertIsNone(self.stored_token())
        self.assertNotIn(OTHER_TOKEN, out + err)
        self.assertNotIn(TOKEN, out + err)

    def test_logout_with_one_copy_is_unchanged(self):
        code, out, err = self.logout()
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, "signed out; removed the stored session from keychain\n")
        self.assertEqual(self.logouts, [TOKEN])

    def test_an_explicit_store_warns_about_the_copy_it_left(self):
        store.file_store(self.path, "portal-token", OTHER_TOKEN)
        code, out, err = self.logout("--store", "keychain")
        self.assertEqual(code, 0)
        self.assertIn("another stored session remains in file", err)
        self.assertIn("config unset portal-token --store file", err)
        self.assertEqual(self.stored_token(), OTHER_TOKEN)                    # left alone, as asked
        self.assertNotIn(OTHER_TOKEN, out + err)


class SecretEchoTests(PortalCase):
    def test_unknown_options_never_repeat_their_values(self):
        for argv in (["--pass=hunter2X"], ["-p", "hunter2X"], ["--passwd", "hunter2X"], ["--pw", "hunter2X"],
                     ["stray-hunter2X"]):
            code, out, err = self.run_cli("portal", "login", "--email", EMAIL, *argv)
            self.assertEqual(code, 2, argv)
            self.assertNotIn("hunter2X", out + err, argv)
        self.assertEqual(self.server.requests, [])
        code, _, err = self.run_cli("portal", "login", "--pass=hunter2X")
        self.assertIn("--pass", err)
        self.assertIn("values are not shown", err)

    def test_other_unrecognized_arguments_still_fail_with_the_option_name(self):
        code, _, err = self.run_cli("config", "check", "--bogus", "1")
        self.assertEqual(code, 2)
        self.assertIn("--bogus", err)

    def test_password_stdin_on_a_terminal_is_refused_not_echoed(self):
        code, out, err = self.login("--email", EMAIL, "--password-stdin", stdin=TTY(PASSWORD + "\n"))
        self.assertEqual(code, 2)
        self.assertIn("piped input", err)
        self.assertEqual(self.server.requests, [])
        self.assertClean(out, err)

    def test_token_set_from_stdin_on_a_terminal_is_refused(self):
        code, out, err = self.run_cli("portal", "token-set", "--store", "file", "--from-stdin", stdin=TTY(TOKEN + "\n"))
        self.assertEqual(code, 2)
        self.assertIn("piped input", err)
        self.assertIsNone(self.stored_token())
        self.assertNotIn(TOKEN, out + err)

    def test_the_plain_password_never_reaches_the_redactor(self):
        added = []
        real_add = Redactor.add
        self.server.routes["/api/v1/user/login"] = lambda rec: ok({"token": TOKEN})

        def spy(self_, *values):
            added.extend(values)
            return real_add(self_, *values)
        with mock.patch.object(Redactor, "add", spy):
            code, out, err = self.login("--email", EMAIL, "--password-stdin", stdin=io.StringIO(PASSWORD + "\n"))
        self.assertEqual(code, 0, err)
        self.assertNotIn(PASSWORD, added)
        self.assertIn(PW_HASH, added)
        self.assertIn(EMAIL, added)


class ImsiMaskingTests(unittest.TestCase):
    IMSI = "001010000000001"

    def test_any_imsi_named_key_is_masked(self):
        out = output.sanitize({"imsiList": self.IMSI, "IMSI_2": self.IMSI, "subscriberImsi": 1, "imsi": self.IMSI,
                               "imsis": [self.IMSI, self.IMSI]})
        self.assertNotIn(self.IMSI, json.dumps(out))
        self.assertEqual(out["imsiList"], "****0001")
        self.assertEqual(out["imsis"], ["****0001", "****0001"])

    def test_eid_and_ac_name_variants_are_masked_but_not_look_alikes(self):
        out = output.sanitize({"eidList": "ABCDEF12", "eid": "ABCDEF12", "acString": "1$h$XYZ12345",
                               "activationCodeText": "LPA-ish-12345", "heidi": "plain", "provider": "plain"})
        self.assertEqual((out["eidList"], out["eid"]), ("****EF12", "****EF12"))
        self.assertEqual(out["acString"], "****2345")
        self.assertEqual(out["activationCodeText"], "****2345")
        self.assertEqual((out["heidi"], out["provider"]), ("plain", "plain"))

    def test_free_text_imsi_shape_is_masked_only_when_asked(self):
        text = "imsi 001010000000002 iccid 8999000000000012345"
        self.assertEqual(output.mask_text(text), text)                       # the main CLI is unchanged
        masked = output.mask_text(text, imsi_text=True)
        self.assertNotIn("001010000000002", masked)
        self.assertIn("8999000000000012345", masked)                         # a 19-digit ICCID is not an IMSI

    def test_phone_number_fields_are_left_alone(self):
        out = output.sanitize({"msisdn": "447700900123456", "notes": "call 447700900123456"}, imsi_text=True)
        self.assertEqual(out["msisdn"], "447700900123456")
        self.assertNotIn("447700900123456", out["notes"])


class ImsiThroughThePortalTests(PortalCase):
    def test_fleet_json_masks_imsi_under_other_names_and_in_notes(self):
        self.signed_in()
        self.server.routes["/api/v1/fleet/list"] = paged(
            [row(1, imsiList="001010000000001", notes="imsi 001010000000002")])
        code, out, err = self.run_cli("portal", "fleet", "--json")
        self.assertEqual(code, 0, err)
        for imsi in ("001010000000001", "001010000000002"):
            self.assertNotIn(imsi, out)

    def test_logs_mask_free_text_imsi(self):
        self.signed_in()
        self.server.routes["/api/v1/log/profile/list"] = lambda rec: ok(
            {"pageData": [{"iccid": "89990000000000001", "status": "ERROR", "reason": "bad imsi 001010000000003"}]})
        code, out, err = self.run_cli("portal", "logs")
        self.assertEqual(code, 0, err)
        self.assertNotIn("001010000000003", out)
        code, out, err = self.run_cli("portal", "logs", "--json")
        self.assertNotIn("001010000000003", out)


if __name__ == "__main__":
    unittest.main()
