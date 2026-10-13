import re
import unittest

import support  # noqa: F401  (sets up sys.path and the network guard)
from simlessly_cli import auth


class SigningTests(unittest.TestCase):
    # The docs' only worked example gives neither the secret nor the body, so it cannot be
    # reproduced. This vector was computed independently with:
    #   printf '%s' "$TS$RID$AK$BODY" | openssl dgst -sha256 -hmac SECRET_demo   (then upper-cased)
    TS = "1790000000000"
    RID = "11111111-2222-3333-4444-555555555555"
    AK = "AK_demo"
    BODY = '{"iccid":"8999000000000000001"}'
    EXPECTED = "674D72C37B478B5FDB287E77CFE8B758000E25343F93A774538DB69D3C2CEFB7"

    def test_fixed_vector(self):
        self.assertEqual(auth.sign("SECRET_demo", self.TS, self.RID, self.AK, self.BODY), self.EXPECTED)

    def test_string_to_sign_order_is_timestamp_requestid_accesskey_body(self):
        base = auth.sign("s", "1", "2", "3", "4")
        self.assertNotEqual(base, auth.sign("s", "2", "1", "3", "4"))
        self.assertEqual(base, auth.sign("s", "12", "", "3", "4"))  # plain concatenation, no separators

    def test_signature_is_64_uppercase_hex(self):
        self.assertRegex(auth.sign("s", "1", "2", "3", "4"), r"^[0-9A-F]{64}$")

    def test_headers(self):
        h = auth.build_headers(self.AK, "SECRET_demo", self.BODY, timestamp=self.TS, request_id=self.RID)
        self.assertEqual(h, {"Content-Type": "application/json", "AccessKey": self.AK, "Timestamp": self.TS,
                             "RequestID": self.RID, "Signature": self.EXPECTED})

    def test_timestamp_is_13_digit_milliseconds_and_ids_are_unique(self):
        self.assertRegex(auth.new_timestamp(), r"^\d{13}$")
        ids = {auth.new_request_id() for _ in range(50)}
        self.assertEqual(len(ids), 50)
        self.assertTrue(all(re.fullmatch(support.UUID_RE.pattern, i) for i in ids))

    def test_body_change_changes_signature(self):
        self.assertNotEqual(auth.sign("s", "1", "2", "3", '{"a":1}'), auth.sign("s", "1", "2", "3", '{"a": 1}'))


if __name__ == "__main__":
    unittest.main()
