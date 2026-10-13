import unittest

import support  # noqa: F401
from simlessly_cli.output import (Redactor, kv, mask_tail, mask_text, normalize_status, sanitize, status_meaning,
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
