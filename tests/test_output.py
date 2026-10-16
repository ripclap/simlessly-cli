import unittest

import support  # noqa: F401
from simlessly_cli.output import (Redactor, clean, kv, mask_tail, mask_text, normalize_status, sanitize, status_meaning,
                                  table)


class MaskingTests(unittest.TestCase):
    def test_mask_tail(self):
        self.assertEqual(mask_tail("1$host$ABCDEF123456"), "****3456")
        self.assertEqual(mask_tail("abcd"), "****")
        self.assertEqual(mask_tail(""), "****")

    def test_sanitize_masks_and_redacts(self):
        obj = {"ki": "K" * 32, "opc": "O" * 32, "iccid": "899", "eid": "E" * 32, "ac": "1$h$MATCH1234",
               "nested": [{"activationCode": "1$h$ZZZZ9999", "pin1": "1234"}], "empty": {"ki": ""}}
        out = sanitize(obj)
        self.assertEqual(out["ki"], "[redacted]")
        self.assertEqual(out["eid"], "****" + "E" * 4)
        self.assertEqual(out["ac"], "****1234")
        self.assertEqual(out["nested"][0], {"activationCode": "****9999", "pin1": "[redacted]"})
        self.assertEqual(out["empty"], {"ki": ""})  # empty stays visible: shows exactly what is sent
        self.assertEqual(out["iccid"], "899")

    def test_reveal_only_unmasks_mask_keys_never_secrets(self):
        out = sanitize({"ac": "1$h$MATCH1234", "ki": "K" * 32}, reveal=True)
        self.assertEqual(out, {"ac": "1$h$MATCH1234", "ki": "[redacted]"})

    def test_mask_text_scrubs_codes_hex_and_known_secrets(self):
        r = Redactor()
        r.add("hunter2-secret")
        text = f"bad 1$rsp-eu.simlessly.com$ABCDEF eid {'1' * 32} key hunter2-secret end"
        out = mask_text(text, r)
        self.assertNotIn("ABCDEF", out)
        self.assertNotIn("1" * 32, out)
        self.assertNotIn("hunter2-secret", out)

    def test_table_and_kv_align(self):
        self.assertEqual(table(["a", "bb"], [["1", "2"], ["333", "4"]]).splitlines()[0], "a    bb")
        self.assertEqual(kv([("a", 1), ("bbb", 2)]).splitlines(), ["a    1", "bbb  2"])


CONTROLS = "\x1b\x7f\x80\x85\x9b\x9d\x9f\u2028\u2029"
BIDI = "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
UNSAFE = CONTROLS + BIDI
PRINTABLE = "caf\u00e9 na\u00efve \u00a0nbsp \u65e5\u672c\u8a9e \U0001f600 \u0627\u0644 \u2019q\u2019 \u00a1\u00bf"


class CleanTests(unittest.TestCase):
    def test_controls_and_separators_become_a_space(self):
        for ch in CONTROLS:
            self.assertEqual(clean("a" + ch + "b"), "a b", hex(ord(ch)))
        self.assertEqual(clean("a\nb\tc\x00d"), "a b c d")

    def test_bidi_marks_and_controls_are_removed(self):
        for ch in BIDI:
            self.assertEqual(clean("a" + ch + "b"), "ab", hex(ord(ch)))
        # A right-to-left name with its marks keeps its shape (no extra spaces).
        self.assertEqual(clean("\u05e9\u05dc\u05d5\u05dd\u200f (x)"), "\u05e9\u05dc\u05d5\u05dd (x)")

    def test_ordinary_printable_characters_survive(self):
        self.assertEqual(clean(PRINTABLE), PRINTABLE)

    def test_limit_still_applies(self):
        self.assertEqual(clean("abcdef", 4), "abc\u2026")

    def test_tables_and_key_value_lists_never_show_them(self):
        text = table(["h"], [["x" + UNSAFE + "y"], [PRINTABLE]]) + kv([("k", "x" + UNSAFE + "y")])
        for ch in UNSAFE:
            self.assertNotIn(ch, text, hex(ord(ch)))
        self.assertIn(PRINTABLE, text)


class StatusTests(unittest.TestCase):
    def test_not_proof_states(self):
        for s in ("AVAILABLE", "EXPIRED", "CANCELED", "REMOVED", "cancelled", "available"):
            self.assertIn("not proof the eSIM left the phone", status_meaning(s), s)

    def test_other_states_have_no_caveat(self):
        for s in ("ENABLED", "DISABLED", "INSTALLED", "DOWNLOADED", "DELETED", "ERROR"):
            self.assertNotIn("not proof", status_meaning(s), s)

    def test_folding_and_unknown(self):
        self.assertEqual(normalize_status("enable"), "ENABLED")
        self.assertEqual(normalize_status("Delete"), "DELETED")
        self.assertIn("unrecognised", status_meaning("WEIRD"))


if __name__ == "__main__":
    unittest.main()
