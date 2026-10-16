import io
import json
import re

import support
from support import AC, AC_LINK, EID, ICCID, IMSI, KI, OPC, CliTestCase, ok

GEN_ARGS = ["ac", "generate", "--config", "demo-config", "--iccid", ICCID, "--imsi", IMSI]


class DryRunTests(CliTestCase):
    """Every state-changing command: no --yes means exit 2, a preview, and no requests."""

    def commands(self):
        self.env.update({"SIMLESSLY_SIM_KI": KI, "SIMLESSLY_SIM_OPC": OPC})
        return [
            GEN_ARGS,
            ["profile", "expire", ICCID],
            ["profile", "delete", ICCID],
            ["order", "cancel", ICCID],
            ["order", "download", ICCID, "--config", "demo-config"],
            ["order", "confirm", ICCID],
        ]

    def test_all_dry_run_by_default(self):
        for argv in self.commands():
            with self.subTest(argv=argv):
                code, out, err = self.run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertTrue(out.startswith("Dry run"), out)
                self.assertIn("add --yes", out)
                self.assertEqual(err, "")
                self.assertIn("POST " + self.server.url, out)
                self.assertNoSecrets(out, err)
        self.assertEqual(self.server.requests, [])

    def test_dry_run_needs_no_credentials(self):
        code, out, err = self.run_cli("profile", "delete", ICCID, env={"SIMLESSLY_NO_KEYCHAIN": "1"})
        self.assertEqual(code, 2)
        self.assertIn("https://rsp.simlessly.com/api/v1/profile/delete", out)
        self.assertIn('"force":false', out)

    def test_dry_run_json(self):
        code, out, err = self.run_cli("profile", "expire", ICCID, "--json")
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertTrue(data["dry_run"])
        self.assertEqual(data["body"], {"iccid": ICCID})
        self.assertIn("dry run", err)

    def test_generate_preview_redacts_sim_secrets(self):
        self.env.update({"SIMLESSLY_SIM_KI": KI, "SIMLESSLY_SIM_OPC": OPC})
        code, out, err = self.run_cli(*GEN_ARGS)
        self.assertEqual(code, 2)
        self.assertIn('"ki":"[redacted]"', out)
        self.assertIn('"opc":"[redacted]"', out)
        self.assertIn("may cost money", out)
        self.assertNoSecrets(out, err)


class GenerateTests(CliTestCase):
    def setUp(self):
        super().setUp()
        self.env.update({"SIMLESSLY_SIM_KI": KI, "SIMLESSLY_SIM_OPC": OPC})
        self.server.routes["/api/v2/ac/generate"] = lambda r: ok({"iccid": ICCID, "activationCode": AC, "acLink": AC_LINK})

    def test_yes_sends_exact_body_once_and_reveals_code_only_with_flag(self):
        code, out, err = self.run_cli(*GEN_ARGS, "--yes", "--reveal-ac")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.server.requests[0].body, json.dumps(
            {"iccid": ICCID, "imsi": IMSI, "ki": KI, "opc": OPC, "needAcLink": True, "configName": "demo-config"},
            separators=(",", ":")))
        self.assertAllSigned()
        self.assertIn(AC, out)
        self.assertIn("LPA:" + AC, out)
        self.assertIn(AC_LINK, out)
        self.assertIn("bearer secret", err)
        self.assertNoSecrets(out, err)  # the code is shown; the SIM keys and credentials never are

    def test_yes_alone_masks_code_link_and_lpa_payload(self):
        code, out, err = self.run_cli(*GEN_ARGS, "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.server.requests), 1)
        for secret in (AC, AC_LINK, "LPA:" + AC, "ABCDEF0123456789"):
            self.assertNotIn(secret, out + err)
        self.assertIn("****6789", out)
        self.assertIn("--reveal-ac", err)
        self.assertNotIn("bearer secret", err)
        self.assertNoSecrets(out, err)

    def test_yes_alone_masks_in_json_too(self):
        code, out, err = self.run_cli(*GEN_ARGS, "--yes", "--json")
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(data["activationCode"], "****6789")
        self.assertNotIn(AC_LINK, out)
        self.assertNotIn(AC, out)

    def test_dry_run_needs_no_sim_secrets_and_never_prompts(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        import getpass
        orig = getpass.getpass
        getpass.getpass = lambda *a, **k: self.fail("a dry run must not prompt")
        try:
            for key in ("SIMLESSLY_SIM_KI", "SIMLESSLY_SIM_OPC"):
                del self.env[key]
            for stdin in (None, Tty()):
                code, out, err = self.run_cli(*GEN_ARGS, stdin=stdin)
                self.assertEqual(code, 2)
                self.assertIn("Dry run", out)
                self.assertIn('"ki":"[redacted]"', out)
                self.assertIn("ki show as [redacted]", out)
                self.assertNotIn("opc", out)
                self.assertIn("add --yes", out)
                self.assertNotIn("is required", err)
        finally:
            getpass.getpass = orig
        self.assertEqual(self.server.requests, [])

    def test_dry_run_still_rejects_a_malformed_secret_that_was_given(self):
        self.env["SIMLESSLY_SIM_KI"] = "not-hex"
        code, _, err = self.run_cli(*GEN_ARGS)
        self.assertEqual(code, 2)
        self.assertNotIn("dry run", err)

    def test_optional_fields_and_no_ac_link(self):
        code, out, _ = self.run_cli(*GEN_ARGS, "--msisdn", "15551234567", "--no-ac-link", "--yes")
        self.assertEqual(code, 0)
        body = json.loads(self.server.requests[0].body)
        self.assertEqual((body["msisdn"], body["needAcLink"]), ("15551234567", False))

    def test_opc_omitted_when_not_given(self):
        del self.env["SIMLESSLY_SIM_OPC"]
        self.assertEqual(self.run_cli(*GEN_ARGS, "--yes")[0], 0)
        self.assertNotIn("opc", json.loads(self.server.requests[0].body))

    def test_config_from_environment(self):
        self.env["SIMLESSLY_CONFIG_NAME"] = "env-config"
        argv = [a for a in GEN_ARGS if a not in ("--config", "demo-config")]
        self.assertEqual(self.run_cli(*argv, "--yes")[0], 0)
        self.assertEqual(json.loads(self.server.requests[0].body)["configName"], "env-config")

    def test_missing_config_ki_or_bad_values_are_usage_errors(self):
        no_config = [a for a in GEN_ARGS if a not in ("--config", "demo-config")]
        self.assertEqual(self.run_cli(*no_config, "--yes")[0], 2)
        del self.env["SIMLESSLY_SIM_KI"]
        code, _, err = self.run_cli(*GEN_ARGS, "--yes")
        self.assertEqual(code, 2)
        self.assertIn("SIMLESSLY_SIM_KI", err)
        self.env["SIMLESSLY_SIM_KI"] = "not-hex"
        code, _, err = self.run_cli(*GEN_ARGS, "--yes")
        self.assertEqual(code, 2)
        self.assertNotIn("not-hex", err)
        self.env["SIMLESSLY_SIM_KI"] = KI
        bad = ["ac", "generate", "--config", "c", "--iccid", "123", "--imsi", IMSI]
        self.assertEqual(self.run_cli(*bad, "--yes")[0], 2)
        self.assertEqual(self.server.requests, [])

    def test_ki_flag_warns_about_history_and_is_still_hidden(self):
        del self.env["SIMLESSLY_SIM_KI"]
        code, out, err = self.run_cli(*GEN_ARGS, "--ki", KI)
        self.assertEqual(code, 2)
        self.assertIn("shell history", err)
        self.assertNotIn(KI, out + err)

    def test_json_output_reveals_code_only_with_reveal_flag(self):
        code, out, _ = self.run_cli(*GEN_ARGS, "--yes", "--json", "--reveal-ac")
        self.assertEqual(json.loads(out)["activationCode"], AC)
        self.assertNoSecrets(out)

    def test_answer_without_code_is_unknown_outcome(self):
        self.server.routes["/api/v2/ac/generate"] = lambda r: ok({"iccid": ICCID})
        code, _, err = self.run_cli(*GEN_ARGS, "--yes")
        self.assertEqual(code, 3)
        self.assertIn("OUTCOME UNKNOWN", err)

    def test_prompts_for_secrets_on_a_terminal(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        import getpass
        answers = iter([KI, ""])
        orig = getpass.getpass
        getpass.getpass = lambda prompt="", stream=None: next(answers)
        try:
            del self.env["SIMLESSLY_SIM_KI"], self.env["SIMLESSLY_SIM_OPC"]
            code, out, err = self.run_cli(*GEN_ARGS, "--yes", stdin=Tty())
        finally:
            getpass.getpass = orig
        self.assertEqual(code, 0, err)
        body = json.loads(self.server.requests[0].body)
        self.assertEqual(body["ki"], KI)
        self.assertNotIn("opc", body)


class OtherMutationTests(CliTestCase):
    def sent(self, path):
        return [r for r in self.server.requests if r.path == path]

    def test_expire(self):
        self.server.routes["/api/v1/profile/expired"] = lambda r: ok(None)
        code, out, err = self.run_cli("profile", "expire", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.sent("/api/v1/profile/expired")[0].body, '{"iccid":"%s"}' % ICCID)
        self.assertIn("not proof the eSIM left the phone", out)
        self.assertAllSigned()

    def test_delete_never_sends_force_true(self):
        self.server.routes["/api/v1/profile/delete"] = lambda r: ok({"iccid": ICCID})
        code, out, err = self.run_cli("profile", "delete", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.sent("/api/v1/profile/delete")[0].body, '{"iccid":"%s","force":false}' % ICCID)
        self.assertNotEqual(self.run_cli("profile", "delete", ICCID, "--yes", "--force")[0], 0)
        self.assertEqual(len(self.server.requests), 1)

    def test_order_flow_paths_and_bodies(self):
        for path in ("cancelOrder", "downloadOrder"):
            self.server.routes["/gsma/rsp2/es2plus/" + path] = lambda r: ok(None)
        self.server.routes["/gsma/rsp2/es2plus/confirmOrder"] = lambda r: ok({"eid": EID, "ac": AC})
        self.assertEqual(self.run_cli("order", "cancel", ICCID, "--yes")[0], 0)
        self.assertEqual(self.run_cli("order", "download", ICCID, "--config", "demo-config", "--yes")[0], 0)
        code, out, err = self.run_cli("order", "confirm", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual([r.body for r in self.server.requests], [
            '{"iccid":"%s"}' % ICCID,
            '{"iccid":"%s","configName":"demo-config"}' % ICCID,
            '{"iccid":"%s","confirmationCode":"","ac":""}' % ICCID,
        ])
        self.assertAllSigned()
        self.assertNotIn(AC, out)           # masked by default
        self.assertNotIn(EID, out)
        self.assertIn("****6789", out)

    def test_confirm_reveal_ac(self):
        self.server.routes["/gsma/rsp2/es2plus/confirmOrder"] = lambda r: ok({"eid": EID, "ac": AC})
        code, out, err = self.run_cli("order", "confirm", ICCID, "--yes", "--reveal-ac")
        self.assertIn(AC, out)
        self.assertIn("bearer secret", err)

    def test_confirm_without_code_in_answer(self):
        self.server.routes["/gsma/rsp2/es2plus/confirmOrder"] = lambda r: ok(None)
        code, out, _ = self.run_cli("order", "confirm", ICCID, "--yes")
        self.assertEqual(code, 0)
        self.assertIn("returned no activation code", out)

    def test_download_needs_config(self):
        code, _, err = self.run_cli("order", "download", ICCID, "--yes")
        self.assertEqual(code, 2)
        self.assertEqual(self.server.requests, [])


class SentConfirmationTests(CliTestCase):
    def setUp(self):
        super().setUp()
        self.env.update({"SIMLESSLY_SIM_KI": KI, "SIMLESSLY_SIM_OPC": OPC})
        self.server.routes["/api/v2/ac/generate"] = lambda r: ok({"iccid": ICCID, "activationCode": AC, "acLink": AC_LINK})
        self.server.routes["/gsma/rsp2/es2plus/confirmOrder"] = lambda r: ok({"eid": EID, "ac": AC})

    def assertOrder(self, text, *parts):
        positions = [text.index(part) for part in parts]
        self.assertEqual(positions, sorted(positions), (parts, text))

    def test_ac_generate_prints_sent_then_the_result_block_then_request_and_next_step(self):
        code, out, err = self.run_cli(*GEN_ARGS, "--yes")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith(f"Sent. Created a profile and activation code for ICCID {ICCID}.\n\n"), out)
        self.assertNotIn("Generated.", out)
        self.assertOrder(out, "Sent.", "ICCID", "Activation code", "QR payload (LPA)", "QR image link",
                         "Request  POST " + self.server.url + "/api/v2/ac/generate",
                         f"Then:    simlessly profile show {ICCID}")
        self.assertIn("****6789", out)
        for secret in (AC, AC_LINK):
            self.assertNotIn(secret, out + err)
        self.assertNoSecrets(out, err)
        code, out, err = self.run_cli(*GEN_ARGS, "--yes", "--reveal-ac")
        self.assertRegex(out, r"Activation code +" + re.escape(AC))
        self.assertTrue(out.startswith("Sent."), out)

    def test_order_confirm_prints_sent_then_the_result_block_then_request_and_next_step(self):
        code, out, err = self.run_cli("order", "confirm", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith(f"Sent. Confirmed {ICCID}. New code issued.\n\n"), out)
        self.assertOrder(out, "Sent.", "Activation code", "EID",
                         "Request  POST " + self.server.url + "/gsma/rsp2/es2plus/confirmOrder",
                         f"Then:    simlessly profile show {ICCID}")
        self.assertIn("****6789", out)
        self.assertNotIn(AC, out)
        self.assertNotIn(EID, out)
        code, out, err = self.run_cli("order", "confirm", ICCID, "--yes", "--reveal-ac")
        self.assertRegex(out, r"Activation code +" + re.escape(AC))

    def test_order_confirm_without_a_code_still_says_sent_and_what_to_do_next(self):
        self.server.routes["/gsma/rsp2/es2plus/confirmOrder"] = lambda r: ok(None)
        code, out, err = self.run_cli("order", "confirm", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith(f"Sent. Confirmed {ICCID}, but Simlessly returned no activation code."), out)
        self.assertIn(f"Then:    simlessly profile show {ICCID}", out)

    def test_json_output_is_unchanged(self):
        code, out, err = self.run_cli(*GEN_ARGS, "--yes", "--json")
        self.assertEqual(json.loads(out), {"iccid": ICCID, "activationCode": "****6789",
                                           "acLink": "****" + AC_LINK[-4:]})
        code, out, err = self.run_cli("order", "confirm", ICCID, "--yes", "--json")
        self.assertEqual(json.loads(out), {"eid": "****" + EID[-4:], "ac": "****6789"})


class OrderCancelNextStepTests(CliTestCase):
    def then_lines(self, out):
        lines = out.rstrip("\n").split("\n")
        return lines[lines.index(next(ln for ln in lines if ln.startswith("Then:"))):]

    def test_a_known_config_is_quoted_into_the_next_step(self):
        self.env["SIMLESSLY_CONFIG_NAME"] = "My Config; rm -rf x"
        code, out, err = self.run_cli("order", "cancel", ICCID)
        self.assertEqual(code, 2)
        self.assertIn(f"Then:     simlessly order download {ICCID} --config 'My Config; rm -rf x'\n", out)
        for line in self.then_lines(out):                # a next step is previewed first, never pre-approved
            self.assertNotIn("--yes", line)
        self.assertNotIn("CONFIG_NAME", out)
        self.assertNotIn("requires --config", out)
        self.server.routes["/gsma/rsp2/es2plus/cancelOrder"] = lambda r: ok(None)
        code, out, err = self.run_cli("order", "cancel", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.then_lines(out), [
            f"Then:    simlessly order download {ICCID} --config 'My Config; rm -rf x'",
            f"         simlessly order confirm {ICCID}"])

    def test_an_unknown_config_gets_a_placeholder_that_cannot_send_anything_and_a_note(self):
        self.assertNotIn("SIMLESSLY_CONFIG_NAME", self.env)
        code, out, err = self.run_cli("order", "cancel", ICCID)
        self.assertEqual(code, 2)
        self.assertIn(f"Then:     simlessly order download {ICCID} --config CONFIG_NAME\n", out)
        self.assertNotIn("<name>", out)
        self.assertIn("requires --config", out)
        self.assertIn("replace CONFIG_NAME", out)
        self.server.routes["/gsma/rsp2/es2plus/cancelOrder"] = lambda r: ok(None)
        code, out, err = self.run_cli("order", "cancel", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertIn(f"simlessly order download {ICCID} --config CONFIG_NAME\n", out)
        self.assertNotIn("CONFIG_NAME --yes", out)


class PreviewTests(CliTestCase):
    def test_preview_shows_what_is_sent_without_nulls_or_masked_ids(self):
        self.env.update({"SIMLESSLY_SIM_KI": KI})
        code, out, _ = self.run_cli(*GEN_ARGS)
        self.assertEqual(code, 2)
        self.assertNotIn("null", out)
        self.assertIn('"imsi":"%s"' % IMSI, out)
        self.assertNotIn('"opc"', out)
