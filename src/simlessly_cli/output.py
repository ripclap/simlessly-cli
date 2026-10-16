"""Output formatting: masking, redaction, tables and status meanings.

Everything printed passes through here. Secret keys (SIM keys, PINs, UPP, credentials) become
"[redacted]". Mask keys (activation codes, QR links, EIDs, IMSIs) keep their last 4 characters unless
revealed. Vendor free text is scrubbed for credential-looking strings.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Sequence

# Always printed as "[redacted]" (compared case-insensitively).
SECRET_KEYS = {
    "ki", "opc", "pin1", "pin2", "puk1", "puk2", "adm1", "upp", "secret",
    "secretkey", "clientsecret", "c9", "cc", "signature",
    # portal login body and session token
    "password", "token", "activetoken", "email",
}
# Last 4 characters only unless revealed.
MASK_KEYS = {
    "ac", "activationcode", "aclink", "activation", "matchingid",
    "confirmationcode", "eid", "imsi", "acstring",
    # portal links to files holding activation codes or error reports
    "acurl", "resulturl",
}
# The subset of MASK_KEYS that --reveal-ac may show.
AC_KEYS = {"ac", "acstring", "activationcode", "aclink", "activation", "matchingid", "confirmationcode", "acurl"}

_AC_RE = re.compile(r"(?:LPA:)?1\$[^\s$\"']+\$[^\s$\"']+(?:\$[^\s$\"']*)*", re.IGNORECASE)
_LONG_HEX_RE = re.compile(r"\b[0-9A-Fa-f]{32,}\b")  # EIDs, KI/OPc-shaped values
_IMSI_RE = re.compile(r"(?<![\d+])\d{15}(?!\d)")        # 15 digits (ICCIDs have 19-20)
# Names that also count as mask keys: containing imsi / acstring / activationcode, or "eid" as its own
# word (eid, eidList, EID_value; not "heidi").
_MASK_NAME_PARTS = ("imsi", "acstring", "activationcode")
_EID_NAME_RE = re.compile(r"(?<![a-z])[Ee][Ii][Dd](?![a-z])")


def is_mask_key(key: Any) -> bool:
    name = str(key)
    lower = name.lower()
    return lower in MASK_KEYS or any(part in lower for part in _MASK_NAME_PARTS) or bool(_EID_NAME_RE.search(name))


def mask_tail(value: Any) -> str:
    """Hide everything except the last 4 characters: '1$host$ABCDEF' -> '****CDEF'."""
    text = str(value)
    return "****" + text[-4:] if len(text) > 4 else "****"


class Redactor:
    """Removes known secret values (credentials, SIM keys) from any text."""

    def __init__(self) -> None:
        self._secrets: list[str] = []

    def add(self, *values: str | None) -> None:
        for value in values:
            if value and len(value) >= 4 and value not in self._secrets:
                self._secrets.append(value)
                self._secrets.sort(key=len, reverse=True)  # longest first

    def scrub(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[redacted]")
        return text


def mask_text(text: str, redactor: Redactor | None = None, imsi_text: bool = False) -> str:
    """Scrub free text: known secrets, activation-code shapes and 32+ hex runs (plus 15-digit runs with imsi_text)."""
    if redactor is not None:
        text = redactor.scrub(text)
    text = _AC_RE.sub(lambda m: mask_tail(m.group(0)), text)
    text = _LONG_HEX_RE.sub(lambda m: mask_tail(m.group(0)), text)
    return _IMSI_RE.sub(lambda m: mask_tail(m.group(0)), text) if imsi_text else text


# Characters that could move the cursor, hide text or reorder what a terminal shows. C0 and C1 controls and
# the line and paragraph separators become a space; the bidirectional marks and controls are removed, so
# right-to-left names keep their shape. Ordinary printable text is kept.
_UNSAFE_CHARS_RE = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_BIDI_CHARS_RE = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def clean(value: Any, limit: int | None = None) -> str:
    """One line without control characters, for a table cell."""
    text = "" if value is None else str(value)
    text = _UNSAFE_CHARS_RE.sub(" ", _BIDI_CHARS_RE.sub("", text))
    if limit and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def sanitize(obj: Any, redactor: Redactor | None = None, reveal: bool = False, imsi_text: bool = False) -> Any:
    """A printable copy of a JSON value. `reveal` lets mask keys through (never secret keys);
    `imsi_text` also masks 15-digit runs in free text (not under phone-number fields)."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            lower = str(key).lower()
            if lower in SECRET_KEYS and value not in (None, ""):
                out[key] = "[redacted]"
            elif is_mask_key(key) and isinstance(value, (str, int)) and not isinstance(value, bool) and value != "":
                out[key] = str(value) if reveal else mask_tail(value)
            elif is_mask_key(key) and isinstance(value, list) and value and all(
                    isinstance(v, (str, int)) and not isinstance(v, bool) and v != "" for v in value):
                out[key] = [str(v) if reveal else mask_tail(v) for v in value]
            else:
                out[key] = sanitize(value, redactor, reveal, imsi_text and "msisdn" not in lower)
        return out
    if isinstance(obj, list):
        return [sanitize(item, redactor, reveal, imsi_text) for item in obj]
    if isinstance(obj, str):
        return mask_text(obj, redactor, imsi_text)
    return obj


def debug_text(text: str, redactor: Redactor | None, limit: int = 600) -> str:
    """Redacted body text for --debug."""
    try:
        text = json.dumps(sanitize(json.loads(text), redactor), ensure_ascii=False)
    except ValueError:
        text = mask_text(text, redactor)
    return text if len(text) <= limit else text[:limit] + "…"


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- tables

def table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    cells = [[clean(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    def fmt(row: Sequence[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip()
    lines = [fmt(headers), fmt(["-" * w for w in widths])]
    lines += [fmt(r) for r in cells]
    return "\n".join(lines)


def kv(pairs: Iterable[tuple[str, Any]]) -> str:
    pairs = [(k, clean(v)) for k, v in pairs]
    width = max((len(k) for k, _ in pairs), default=0)
    return "\n".join(f"{k.ljust(width)}  {v}" for k, v in pairs)


# ---------------------------------------------------------------- status meanings

NOT_PROOF = "not proof the eSIM left the phone"

# status -> one-line meaning. See README "Profile status".
STATUS_MEANING = {
    "AVAILABLE": "ready to download (also set after a new code is issued, or when deleted from the phone)",
    "AUTHENTICATED": "device authenticated against the platform (recorded only)",
    "DOWNLOADED": "downloaded to the device, not yet installed",
    "INSTALLED": "installed on the device, not enabled",
    "ENABLED": "installed and active on the device",
    "DISABLED": "installed on the device but inactive",
    "DELETED": "removed from the device (the one status reported by the phone itself)",
    "REMOVED": "deleted from the Simlessly platform (Delete Profile call)",
    "EXPIRED": "activation code invalidated on the platform (Expire call)",
    "CANCELED": "order cancelled on the platform (Cancel Order call)",
    "ERROR": "a download or install failed; read the profile log for the reason",
    "LOCKED": "campaign profile in use by a device",
    "IDLE": "campaign profile not yet used",
}
_NOT_PROOF_STATES = {"AVAILABLE", "EXPIRED", "CANCELED", "REMOVED"}


def normalize_status(status: Any) -> str:
    """Upper-case; fold present tense (ENABLE) to past (ENABLED) and CANCELLED to CANCELED."""
    token = str(status or "").strip().upper()
    return {"ENABLE": "ENABLED", "DISABLE": "DISABLED", "DELETE": "DELETED", "CANCELLED": "CANCELED"}.get(token, token)


def status_meaning(status: Any) -> str:
    """'<meaning>' plus ' - not proof the eSIM left the phone' where that applies."""
    token = normalize_status(status)
    meaning = STATUS_MEANING.get(token, "unrecognised status (shown exactly as the vendor sent it)")
    if token in _NOT_PROOF_STATES:
        meaning += f" - {NOT_PROOF}"
    return meaning
