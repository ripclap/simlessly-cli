"""The shared preview, confirmation and refusal text of the state-changing commands: layout, wrapping,
emphasis only on a terminal, plain ASCII fallback, and the facts that must always be shown."""

import io
import json
import unittest

import support
from support import ICCID, KI, OPC, CliTestCase, ok
from simlessly_cli import preview as pv
from simlessly_cli.cli import main


class Tty(io.StringIO):
    def isatty(self):
        return True


class Ascii(io.StringIO):
    encoding = "ascii"


def sample(**kw):
    base = dict(action="Upload sims.xlsx.gpg and create profiles from its records.",
                cost="BILLABLE: creates profiles and uses plan quota", effect="creates profiles",
                method="POST", url="https://rsp.example.test/api/v1/fleet/generateAc",
                rows=[("Config", "Pilot (77)"), ("File", "sims.xlsx.gpg")],
                notes=["first note", "second note"], then=["simlessly portal batch-logs", "simlessly portal fleet"])
    base.update(kw)
    return pv.Preview(**base)


class LookTests(unittest.TestCase):
    def test_width_comes_from_columns_else_100_off_a_terminal(self):
        self.assertEqual(pv.look_for(io.StringIO(), {}).width, 100)
        self.assertEqual(pv.look_for(io.StringIO(), {"COLUMNS": "72"}).width, 72)
        self.assertEqual(pv.look_for(io.StringIO(), {"COLUMNS": "10"}).width, pv.MIN_WIDTH)
        self.assertEqual(pv.look_for(io.StringIO(), {"COLUMNS": "wide"}).width, 100)

    def test_colour_needs_a_terminal_and_no_no_color_and_a_real_term(self):
        self.assertFalse(pv.look_for(io.StringIO(), {}).color)
        self.assertTrue(pv.look_for(Tty(), {}).color)
        self.assertFalse(pv.look_for(Tty(), {"NO_COLOR": "1"}).color)
        self.assertFalse(pv.look_for(Tty(), {"TERM": "dumb"}).color)
        self.assertTrue(pv.look_for(Tty(), {"NO_COLOR": ""}).color)        # an empty NO_COLOR counts as unset

    def test_plain_ascii_when_the_stream_cannot_encode_the_punctuation(self):
        look = pv.look_for(Ascii(), {})
        self.assertEqual((look.sep, look.dots, look.dash), (" | ", "...", "-"))
        text = pv.render_preview(sample(), look)
        self.assertTrue(text.isascii(), text)
        self.assertTrue(text.startswith("Dry run - nothing has been sent."))


class RenderTests(unittest.TestCase):
    PLAIN = pv.Look(width=100, color=False, fancy=True)

    def test_layout(self):
        text = pv.render_preview(sample(), self.PLAIN)
        self.assertEqual(text, "\n".join([
            "Dry run — nothing has been sent.",
            "",
            "Action   Upload sims.xlsx.gpg and create profiles from its records.",
            "Cost     BILLABLE: creates profiles and uses plan quota",
            "Config   Pilot (77)",
            "File     sims.xlsx.gpg",
            "Effect   creates profiles",
            "Request  POST https://rsp.example.test/api/v1/fleet/generateAc",
            "",
            "Notes",
            "  - first note",
            "  - second note",
            "",
            "To send:  add --yes",
            "Then:     simlessly portal batch-logs",
            "          simlessly portal fleet"]))

    def test_headers_and_the_raw_body_only_with_debug(self):
        p = sample(body='{"a":1}', debug_rows=[("Headers", "Content-Type: application/json")])
        self.assertNotIn("Headers", pv.render_preview(p, self.PLAIN))
        self.assertIn("Body     {\"a\":1}", pv.render_preview(p, self.PLAIN))
        self.assertIn("Headers  Content-Type: application/json", pv.render_preview(p, self.PLAIN, debug=True))

    def test_long_values_and_notes_wrap_under_the_value_column_without_cutting_words(self):
        look = pv.Look(width=50, color=False, fancy=True)
        url = "https://rsp.example.test/api/v1/fleet/a-very-long-path-that-cannot-be-split/generateAc"
        text = pv.render_preview(sample(url=url, notes=["word " * 20]), look)
        lines = text.split("\n")
        self.assertIn(url, text)                                          # the URL stays whole
        for line in lines:
            if url not in line:
                self.assertLessEqual(len(line), 50, line)
        hang = [ln for ln in lines if ln.startswith("    word")]          # note continuation lines
        self.assertTrue(hang, text)
        effect = pv.render_preview(sample(effect="x " * 40), look).split("\n")
        idx = next(i for i, ln in enumerate(effect) if ln.startswith("Effect"))
        self.assertTrue(effect[idx + 1].startswith(" " * 9 + "x"), effect[idx:idx + 2])

    def test_emphasis_is_added_on_a_terminal_only(self):
        colour = pv.Look(width=100, color=True, fancy=True)
        text = pv.render_preview(sample(notes=["FORCED (--force): reason", "WARNING: careful"]), colour)
        self.assertIn("\x1b[1mAction", text)                              # bold label
        self.assertIn("\x1b[1;31mBILLABLE\x1b[0m", text)
        self.assertIn("\x1b[1;31mFORCED\x1b[0m", text)
        self.assertIn("\x1b[1;31mWARNING\x1b[0m", text)
        plain = pv.render_preview(sample(notes=["FORCED (--force): reason"]), self.PLAIN)
        self.assertNotIn("\x1b", plain)
        self.assertEqual(text.replace("\x1b[1;31m", "").replace("\x1b[1m", "").replace("\x1b[0m", "").split("\n")[2:5],
                         pv.render_preview(sample(notes=["FORCED (--force): reason", "WARNING: careful"]),
                                           self.PLAIN).split("\n")[2:5])

    def test_sent_confirmation(self):
        text = pv.render_sent("Deleted X.", "POST", "https://h/p", ["simlessly profile show X"], self.PLAIN)
        self.assertEqual(text, "Sent. Deleted X.\n\nRequest  POST https://h/p\nThen:    simlessly profile show X")

    def test_refusal_lists_reasons_and_keeps_the_one_paragraph_form(self):
        r = pv.Refusal(["its status is ENABLED.", "its recycle state is AWAITING"], action="Delete profile X.",
                       website="Are you sure?", override="if you are sure, repeat with --force (and --yes).")
        text = pv.render_refusal(r, self.PLAIN)
        self.assertEqual(text, "\n".join([
            "Refused. Nothing was sent.", "",
            "Action   Delete profile X.",
            "Why      - its status is ENABLED.",
            "         - its recycle state is AWAITING.",
            "Website  \"Are you sure?\"", "",
            "If you are sure, repeat with --force (and --yes)."]))
        self.assertEqual(str(r), "refusing to delete profile X: its status is ENABLED; its recycle state is AWAITING. "
                                 "The website warns: \"Are you sure?\" Nothing was sent. "
                                 "If you are sure, repeat with --force (and --yes).")
        self.assertEqual(r.kind, "refused")
        single = pv.render_refusal(pv.Refusal(["this is a demo profile"]), self.PLAIN)
        self.assertEqual(single, "Refused. Nothing was sent.\n\nWhy  this is a demo profile.")

    def test_outcome_unknown_line_is_unchanged_in_plain_text(self):
        plain = pv.render_unknown("Check it", self.PLAIN)
        self.assertEqual(plain, "OUTCOME UNKNOWN: Simlessly may have acted. Nothing was retried. Check it before sending again.")
        self.assertIn("\x1b[1;31mOUTCOME UNKNOWN\x1b[0m", pv.render_unknown("Check it", pv.Look(color=True)))


UNSAFE = "\x9b\x9d\x85‮ "
PRINTABLE = "café   日本語 \U0001f600"


def assert_clean(test, text):
    for ch in UNSAFE:
        test.assertNotIn(ch, text, hex(ord(ch)))
    test.assertNotIn("\x1b", text)


class ControlCharacterTests(unittest.TestCase):
    PLAIN = pv.Look(width=60, color=False, fancy=True)

    def test_preview_sent_refusal_and_unknown_never_show_them(self):
        bad = "x" + UNSAFE + "y"
        preview = pv.render_preview(
            sample(action=bad, cost=bad, effect=bad, url="https://h/" + bad, rows=[("Config", bad)], body=bad,
                   notes=[bad], then=[bad]), self.PLAIN, debug=True)
        sent = pv.render_sent(bad, "POST", "https://h/" + bad, [bad], self.PLAIN)
        refusal = pv.render_refusal(pv.Refusal([bad, bad], action=bad, website=bad, override=bad), self.PLAIN)
        unknown = pv.render_unknown(bad, self.PLAIN)
        for text in (preview, sent, refusal, unknown):
            assert_clean(self, text)
            self.assertIn("x", text)

    def test_ordinary_unicode_survives(self):
        text = pv.render_preview(sample(effect=PRINTABLE, notes=[PRINTABLE]), self.PLAIN)
        self.assertIn(PRINTABLE, text)
        self.assertIn(PRINTABLE, pv.render_sent(PRINTABLE, None, None, [], self.PLAIN))
        self.assertIn(PRINTABLE, pv.render_refusal(pv.Refusal([PRINTABLE]), self.PLAIN))
        self.assertIn(PRINTABLE, pv.render_unknown(PRINTABLE, self.PLAIN))


class WrapTests(unittest.TestCase):
    NARROW = pv.Look(width=60, color=False, fancy=True)
    HINT = "Check the profile with `simlessly profile show 8999000000000000001` and then the platform's own log"

    def test_unknown_outcome_wraps_to_the_width(self):
        text = pv.render_unknown(self.HINT, self.NARROW)
        lines = text.split("\n")
        self.assertGreater(len(lines), 1)
        for line in lines:
            self.assertLessEqual(len(line), 60, line)
        self.assertTrue(text.startswith("OUTCOME UNKNOWN: Simlessly may have acted."))
        self.assertEqual(" ".join(text.split()), "OUTCOME UNKNOWN: Simlessly may have acted. Nothing was retried. "
                                                  + self.HINT + " before sending again.")

    def test_sent_line_wraps_with_a_hanging_indent(self):
        done = "Re-generate submitted for 8999000000000000001. The portal processes it in the background."
        lines = pv.render_sent(done, None, None, [], self.NARROW).split("\n")
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].startswith("Sent. Re-generate"), lines)
        for line in lines[1:]:
            self.assertTrue(line.startswith(" " * 6) and not line.startswith(" " * 7), line)
        for line in lines:
            self.assertLessEqual(len(line), 60, line)
        self.assertEqual(" ".join(" ".join(lines).split()), "Sent. " + done)

    def test_only_sent_is_bold_with_colour(self):
        look = pv.Look(width=60, color=True, fancy=True)
        done = "Deleted the profile. " + "more words " * 8
        lines = pv.render_sent(done, None, None, [], look).split("\n")
        self.assertTrue(lines[0].startswith("\x1b[1mSent.\x1b[0m Deleted"), lines[0])
        self.assertEqual(lines[0].count("\x1b[1m"), 1)
        self.assertNotIn("\x1b", "".join(lines[1:]))

    def test_sent_detail_sits_between_the_first_line_and_the_request(self):
        text = pv.render_sent("Done.", "POST", "https://h/p", ["simlessly x"], self.NARROW, detail="Key  value")
        self.assertEqual(text, "Sent. Done.\n\nKey  value\n\nRequest  POST https://h/p\nThen:    simlessly x")

    def test_refusal_override_line_wraps(self):
        override = "if you are sure that the profile is off the phone, repeat the command with --force and --yes, please."
        text = pv.render_refusal(pv.Refusal(["a reason"], override=override), self.NARROW)
        lines = text.split("\n")[4:]
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].startswith("If you are sure"), lines)
        for line in lines:
            self.assertLessEqual(len(line), 60, line)

    def test_wrapped_reasons_hang_under_their_text_not_the_dash(self):
        reason = "its status is ENABLED, i.e. the eSIM is on, or possibly on, a phone, so nothing is sent"
        r = pv.Refusal([reason, "its recycle state is AWAITING"], action="Delete profile X.")
        lines = pv.render_refusal(r, pv.Look(width=50, color=False, fancy=True)).split("\n")
        why = next(i for i, ln in enumerate(lines) if ln.startswith("Why"))
        self.assertTrue(lines[why].startswith("Why     - its status"), lines[why])
        cont = lines[why + 1]
        self.assertTrue(cont.startswith(" " * 10) and cont[10] != " ", cont)     # under "its", not under "-"
        self.assertIn(" " * 8 + "- its recycle state is AWAITING.", lines)
        for line in lines:
            self.assertLessEqual(len(line), 50, line)

    def test_the_action_row_ends_with_a_full_stop(self):
        text = pv.render_refusal(pv.Refusal(["a reason"], action="delete profile X"), self.NARROW)
        self.assertIn("Action  Delete profile X.", text)


class LookParsingTests(unittest.TestCase):
    def test_columns_must_be_ascii_decimal(self):
        for bad in ("²", "٣٠", "6e1", "-60", " 60", "60 ", "0", "", "1" * 5000, "６０"):
            self.assertEqual(pv.look_for(io.StringIO(), {"COLUMNS": bad}).width, 100, repr(bad))
        self.assertEqual(pv.look_for(io.StringIO(), {"COLUMNS": "60"}).width, 60)

    def test_look_for_never_raises(self):
        class Broken(io.StringIO):
            def isatty(self):
                raise RuntimeError("no")
        self.assertEqual(pv.look_for(Broken(), {"COLUMNS": "²"}).width, 100)
        self.assertEqual(pv.look_for(io.StringIO(), None).width, 100)
        self.assertEqual(pv.look_for(io.StringIO(), {"COLUMNS": None}).width, 100)


class EmphasisTests(unittest.TestCase):
    COLOUR = pv.Look(width=100, color=True, fancy=True)
    ALERT = "\x1b[1;31m"

    def test_a_phrase_split_by_a_wrap_is_still_highlighted(self):
        for width in range(50, 90):
            look = pv.Look(width=width, color=True, fancy=True)
            plain = pv.Look(width=width, color=False, fancy=True)
            p = sample(notes=["some words that fill the line " * 2 + "OUTCOME UNKNOWN follows here"])
            text = pv.render_preview(p, look)
            self.assertIn("\x1b[1;31mOUTCOME UNKNOWN\x1b[0m", text, width)
            stripped = text.replace("\x1b[1;31m", "").replace("\x1b[1m", "").replace("\x1b[0m", "")
            self.assertEqual(stripped, pv.render_preview(p, plain), width)        # same layout with and without colour
        text = pv.render_unknown("Check it", pv.Look(width=50, color=True, fancy=True))
        self.assertIn("\x1b[1;31mOUTCOME UNKNOWN\x1b[0m", text)

    def test_words_inside_urls_paths_and_identifiers_are_not_highlighted(self):
        for text in ("https://h/BILLABLE/x", "see /var/FORCED", "file.WARNING", "CAUTION_level", "pre-BILLABLE",
                     "BILLABLE-post", "key:WARNING", "WARNING:value", "a/FORCED/b", "x_FORCED", "FORCEDX",
                     "BILLABLE.txt", "https://h/p?OUTCOME_UNKNOWN"):
            self.assertEqual(pv.emphasize(text, self.COLOUR), text, text)

    def test_ordinary_uses_are_highlighted(self):
        for text, word in (("BILLABLE: creates profiles", "BILLABLE"), ("This is FORCED.", "FORCED"),
                           ("(WARNING) careful", "WARNING"), ("CAUTION, read this", "CAUTION"),
                           ("FORCED (--force): reason", "FORCED"), ("WARNING: a plain spreadsheet", "WARNING")):
            self.assertIn(self.ALERT + word + "\x1b[0m", pv.emphasize(text, self.COLOUR), text)

    def test_a_url_in_a_preview_is_left_alone(self):
        look = pv.Look(width=100, color=True, fancy=True)
        text = pv.render_preview(sample(url="https://rsp.example.test/BILLABLE/FORCED/WARNING"), look)
        request = next(ln for ln in text.split("\n") if "rsp.example.test" in ln)
        self.assertNotIn(self.ALERT, request)


class CommandOutputTests(CliTestCase):
    def tty_run(self, *argv, env=None):
        out, err = Tty(), Tty()
        code = main(list(argv), env={**self.env, **(env or {})}, keychain=None, stdout=out, stderr=err, stdin=io.StringIO())
        return code, out.getvalue(), err.getvalue()

    def test_a_dry_run_is_all_on_stdout_and_wraps_to_columns(self):
        code, out, err = self.run_cli("profile", "delete", ICCID, env={**self.env, "COLUMNS": "60"})
        self.assertEqual((code, err), (2, ""))
        lines = out.split("\n")
        self.assertTrue(lines[0].startswith("Dry run"))
        for line in lines:
            if "http" not in line:
                self.assertLessEqual(len(line), 60, line)
        self.assertIn("To send:  add --yes", out)
        self.assertIn(f"Then:     simlessly profile show {ICCID}", out)

    def test_headers_are_hidden_unless_debug(self):
        self.assertNotIn("Headers", self.run_cli("profile", "delete", ICCID)[1])
        code, out, err = self.run_cli("profile", "delete", ICCID, "--debug")
        self.assertIn("Headers  Content-Type: application/json, plus AccessKey, Timestamp, RequestID and Signature", out)
        self.assertNoSecrets(out, err)

    def test_terminal_output_is_emphasised_and_no_color_turns_it_off(self):
        code, out, err = self.tty_run("profile", "delete", ICCID)
        self.assertEqual(code, 2)
        self.assertIn("\x1b[1mAction", out)
        code, out, err = self.tty_run("profile", "delete", ICCID, env={"NO_COLOR": "1"})
        self.assertNotIn("\x1b", out + err)
        code, out, err = self.tty_run("profile", "delete", ICCID, "--json")
        self.assertNotIn("\x1b", out + err)
        self.assertTrue(json.loads(out)["dry_run"])

    def test_secrets_are_listed_as_redacted_not_shown(self):
        self.env.update({"SIMLESSLY_SIM_KI": KI, "SIMLESSLY_SIM_OPC": OPC})
        code, out, err = self.run_cli("ac", "generate", "--config", "demo-config", "--iccid", ICCID,
                                      "--imsi", support.IMSI)
        self.assertIn("Secret values are never printed: ki, opc show as [redacted].", out)
        self.assertNoSecrets(out, err)

    def test_sent_confirmation_names_the_request_and_the_next_step(self):
        self.server.routes["/api/v1/profile/delete"] = lambda r: ok(None)
        code, out, err = self.run_cli("profile", "delete", ICCID, "--yes")
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(out.startswith(f"Sent. Deleted {ICCID} from the platform."), out)
        self.assertIn("Request  POST " + self.server.url + "/api/v1/profile/delete", out)
        self.assertIn(f"Then:    simlessly profile show {ICCID}", out)

    def test_a_malformed_columns_value_is_ignored_and_never_breaks_the_command(self):
        code, out, err = self.run_cli("profile", "delete", ICCID, env={**self.env, "COLUMNS": "²"})
        self.assertEqual((code, err), (2, ""))
        self.assertTrue(out.startswith("Dry run"), out)
        self.assertIn("To send:  add --yes", out)
        self.server.routes["/api/v1/profile/delete"] = lambda r: (503, b"down", {})
        code, out, err = self.run_cli("profile", "delete", ICCID, "--yes", env={**self.env, "COLUMNS": "²"})
        self.assertEqual(code, 3)
        self.assertIn("OUTCOME UNKNOWN: Simlessly may have acted.", err)
        self.assertNotIn("unexpected", err)

    def test_the_unknown_outcome_text_wraps_at_columns(self):
        self.server.routes["/api/v1/profile/delete"] = lambda r: (503, b"down", {})
        code, out, err = self.run_cli("profile", "delete", ICCID, "--yes", env={**self.env, "COLUMNS": "60"})
        self.assertEqual(code, 3)
        text = err[err.index("OUTCOME UNKNOWN"):]
        self.assertGreater(len(text.strip().split("\n")), 1)
        for line in text.split("\n"):
            self.assertLessEqual(len(line), 60, line)

    def test_a_long_sent_line_wraps_at_columns(self):
        self.server.routes["/api/v1/profile/expired"] = lambda r: ok(None)
        code, out, err = self.run_cli("profile", "expire", ICCID, "--yes", env={**self.env, "COLUMNS": "60"})
        self.assertEqual((code, err), (0, ""))
        lines = out.split("\n\n")[0].split("\n")
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].startswith("Sent. Expired"), lines[0])
        for line in lines:
            self.assertLessEqual(len(line), 60, line)
        for line in lines[1:]:
            self.assertTrue(line.startswith(" " * 6), line)

    def test_outcome_unknown_is_emphasised_on_a_terminal(self):
        self.server.routes["/api/v1/profile/delete"] = lambda r: (503, b"down", {})
        code, out, err = self.tty_run("profile", "delete", ICCID, "--yes")
        self.assertEqual(code, 3)
        self.assertIn("\x1b[1;31mOUTCOME UNKNOWN\x1b[0m", err)
        code, out, err = self.run_cli("profile", "delete", ICCID, "--yes")
        self.assertIn("OUTCOME UNKNOWN: Simlessly may have acted.", err)
        self.assertNotIn("\x1b", err)


if __name__ == "__main__":
    unittest.main()
