"""Human-readable text for state-changing commands: the dry-run preview, the "sent" confirmation and refusals.

Every state-changing command (RSP API and portal) renders through this module, so they all look alike:

    Dry run - nothing has been sent.

    Action   Delete profile 8999000000000000001 from the Simlessly platform.
    Cost     no charge documented
    Target   ICCID 8999000000000000001
    Effect   removes the profile ...
    Request  POST https://rsp.simlessly.com/api/v1/profile/delete

    Notes
      - platform-side only; ...

    To send: add --yes
    Then:    simlessly profile show 8999000000000000001

Values wrap to the terminal width with a hanging indent. Bold labels and a highlighted BILLABLE / CAUTION / WARNING /
FORCED / OUTCOME UNKNOWN are used only when the stream is a terminal and NO_COLOR is unset. --json output
does not go through here.
"""

from __future__ import annotations

import re
import shutil
import textwrap
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence, TextIO

from .client import SimlesslyError
from .output import clean

DEFAULT_WIDTH = 100
MIN_WIDTH = 50

_BOLD, _RESET, _ALERT = "\x1b[1m", "\x1b[0m", "\x1b[1;31m"
# The warning words. A word inside a URL, path or identifier (next to / : . _ or -) is left alone: a colon or a
# full stop that ends the word, as in "BILLABLE: creates ...", does not count.
_ALERT_RE = re.compile(r"(?<![\w/:.\-])(BILLABLE|CAUTION|FORCED|OUTCOME UNKNOWN|WARNING)(?![\w/\-]|[:.]\S)")
_PHRASE = "OUTCOME UNKNOWN"
_GLUE = "\x00"        # stands in for the space of a phrase while a line is wrapped; clean() has removed real ones


@dataclass(frozen=True)
class Look:
    """How to print on one stream: its width, whether to use emphasis, and which punctuation it can show."""

    width: int = DEFAULT_WIDTH
    color: bool = False
    fancy: bool = True

    @property
    def sep(self) -> str:
        return " · " if self.fancy else " | "

    @property
    def dots(self) -> str:
        return "…" if self.fancy else "..."

    @property
    def dash(self) -> str:
        return "—" if self.fancy else "-"


def look_for(stream: TextIO, env: Mapping[str, str] | None) -> Look:
    """Width: COLUMNS (ASCII digits only, else ignored), else the terminal's size when the stream is a terminal,
    else 100. Emphasis: only on a terminal, with NO_COLOR unset (or empty) and TERM not "dumb".
    Never raises: anything unexpected gives the default look."""
    try:
        return _look_for(stream, env if env is not None else {})
    except Exception:
        return Look()


def _look_for(stream: TextIO, env: Mapping[str, str]) -> Look:
    try:
        is_tty = bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        is_tty = False
    width = DEFAULT_WIDTH
    columns = env.get("COLUMNS", "")
    parsed = int(columns) if isinstance(columns, str) and re.fullmatch(r"[0-9]{1,6}", columns) else 0
    if parsed > 0:
        width = parsed
    elif is_tty:
        width = shutil.get_terminal_size((DEFAULT_WIDTH, 24)).columns
    color = is_tty and not env.get("NO_COLOR") and env.get("TERM") != "dumb"
    fancy = True
    encoding = getattr(stream, "encoding", None)
    if encoding:
        try:
            "·…—".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            fancy = False
    return Look(width=max(width, MIN_WIDTH), color=color, fancy=fancy)


def emphasize(text: str, look: Look) -> str:
    """Highlight the warning words when colour is on; the text is unchanged otherwise."""
    return _ALERT_RE.sub(lambda m: _ALERT + m.group(0) + _RESET, text) if look.color else text


def _bold(text: str, look: Look) -> str:
    return _BOLD + text + _RESET if look.color else text


def _wrap(text: str, width: int) -> list[str]:
    """Wrap on spaces only: a long URL or ICCID stays whole (and copyable) rather than being cut mid-word.
    The text is cleaned of control characters, and OUTCOME UNKNOWN is kept on one line so it can be highlighted."""
    text = clean(text).replace(_PHRASE, _PHRASE.replace(" ", _GLUE))
    lines = textwrap.wrap(text, max(width, 20), break_long_words=False, break_on_hyphens=False)
    return [line.replace(_GLUE, " ") for line in lines] or [""]


def _hang(lead: str, text: str, look: Look, shown_lead: str | None = None) -> list[str]:
    """`text` wrapped to the width with `lead` before the first line and spaces of the same width before the others.
    `shown_lead` is `lead` with emphasis added."""
    wrapped = _wrap(text, look.width - len(lead))
    pad = " " * len(lead)
    return [(lead if shown_lead is None else shown_lead) + emphasize(wrapped[0], look),
            *(pad + emphasize(w, look) for w in wrapped[1:])]


def _then_rows(then: Sequence[str]) -> list[tuple[str, str]]:
    """The follow-up commands, one per line under a "Then:" label."""
    return [("Then:" if i == 0 else "", cmd) for i, cmd in enumerate(then)]


def block(rows: Sequence[tuple[str, ...]], look: Look, indent: int = 0) -> list[str]:
    """Aligned "Label  value" lines; a long value wraps under the value column. A row may carry a third item,
    a bullet such as "- ", which goes before the value; the lines of a wrapped value then hang under the text."""
    if not rows:
        return []
    label_width = max(len(row[0]) for row in rows) + 2
    lines: list[str] = []
    for row in rows:
        label, value = row[0], row[1]
        bullet = row[2] if len(row) > 2 else ""
        head = _bold(label.ljust(label_width), look) if look.color else label.ljust(label_width)
        lead = " " * indent + label.ljust(label_width) + bullet
        shown = " " * indent + head + bullet
        lines += _hang(lead, value, look, shown)
    return lines


def bullets(items: Sequence[str], look: Look, indent: int = 2) -> list[str]:
    lines: list[str] = []
    for item in items:
        lines += _hang(" " * indent + "- ", item, look)
    return lines


# ---------------------------------------------------------------- the three texts

@dataclass
class Preview:
    """What a state-changing command would send."""

    action: str                                   # one plain sentence
    cost: str
    effect: str
    method: str
    url: str
    rows: list[tuple[str, str]] = field(default_factory=list)       # specifics, between Cost and Effect
    body: str | None = None                       # compact JSON request body, redacted
    notes: list[str] = field(default_factory=list)
    then: list[str] = field(default_factory=list)                   # follow-up commands
    debug_rows: list[tuple[str, str]] = field(default_factory=list)  # shown only with --debug


def render_preview(p: Preview, look: Look, *, debug: bool = False) -> str:
    rows = [("Action", p.action), ("Cost", p.cost), *p.rows, ("Effect", p.effect),
            ("Request", f"{p.method} {p.url}")]
    if p.body is not None:
        rows.append(("Body", p.body))
    if debug:
        rows += p.debug_rows
    out = [_bold(f"Dry run {look.dash} nothing has been sent.", look), ""]
    out += block(rows, look)
    if p.notes:
        out += ["", _bold("Notes", look), *bullets(p.notes, look)]
    out += ["", *block([("To send:", "add --yes"), *_then_rows(p.then)], look)]
    return "\n".join(out)


def render_sent(done: str, method: str | None, url: str | None, then: Sequence[str], look: Look,
                detail: str | None = None) -> str:
    """The confirmation after a request went through: "Sent." and what happened, then `detail` (a result block
    already laid out, if any), then the request and the next steps."""
    out = _hang("Sent. ", done, look, _bold("Sent.", look) + " ")
    if detail:
        out += ["", detail]
    rows = ([("Request", f"{method} {url}")] if method and url else []) + _then_rows(then)
    if rows:
        out += ["", *block(rows, look)]
    return "\n".join(out)


class Refusal(SimlesslyError):
    """A request this tool will not send, with the reasons kept apart so they can be listed.

    `action` is the sentence that the dry run shows in its Action row ("Delete profile X from the platform.").
    str(refusal) is a one-paragraph form for places that cannot lay it out."""

    def __init__(self, reasons: Sequence[str], *, action: str | None = None, website: str | None = None,
                 override: str | None = None) -> None:
        self.reasons = [r.rstrip(". ") for r in reasons]
        self.action = _sentence(action) if action else None
        self.website = website
        self.override = override
        text = (f"refusing to {self.action[0].lower()}{self.action[1:-1]}: " if self.action else "")
        text += "; ".join(self.reasons) + "."
        if website:
            text += f" The website warns: \"{website}\""
        text += " Nothing was sent."
        if override:
            text += f" {override[0].upper()}{override[1:]}"
        super().__init__(text, kind="refused")


def _sentence(text: str) -> str:
    """Capitalised, with a full stop at the end."""
    text = text.strip()
    text = text[:1].upper() + text[1:]
    return text if text.endswith(".") else text + "."


def render_refusal(r: Refusal, look: Look) -> str:
    rows: list[tuple[str, ...]] = []
    if r.action:
        rows.append(("Action", r.action))
    out = [_bold("Refused.", look) + " Nothing was sent.", ""]
    many = len(r.reasons) > 1
    rows += [("Why" if i == 0 else "", x + ".", "- " if many else "") for i, x in enumerate(r.reasons)]
    if r.website:
        rows.append(("Website", f"\"{r.website}\""))
    out += block(rows, look)
    if r.override:
        out += ["", *_hang("", r.override[:1].upper() + r.override[1:], look)]
    return "\n".join(out)


def render_unknown(hint: str, look: Look) -> str:
    """The text printed when a state-changing request may or may not have been applied."""
    text = f"OUTCOME UNKNOWN: Simlessly may have acted. Nothing was retried. {hint} before sending again."
    return "\n".join(_hang("", text, look))


def pluralize(count: Any, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")
