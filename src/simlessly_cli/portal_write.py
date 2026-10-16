"""`simlessly portal ...`: the state-changing commands (notes, groups, re-generate, recycle, delete, generate-ac).

The only module that reaches a state-changing portal path (portal.WRITE_METHODS), and only through
`portal_mutate()`, the counterpart of cli.mutate():

* Without --yes it prints what would be sent (secrets redacted) and exits 2. A dry run still makes
  read-only calls: it looks the profile up by ICCID for its portal id and status.
* With --yes the request is sent once, never retried. A lost answer exits 3 (outcome unknown).
* One ICCID per call; no batch operations.
* delete, re-generate and recycle first read the profile's status and recycle row. Without --force,
  delete and re-generate proceed only for a status known to be off the phone (AVAILABLE, DELETED, ERROR)
  and a recycle state other than AWAITING (RECYCLED, INVALID); anything else is refused, with the
  website's warning text where it has one. Demo rows are always refused, as are campaign and
  pre-occupied rows for delete and re-generate, even with --force.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any

from . import portal
from .cli import DryRun, Ctx, UsageError, _check, iccid_arg
from .client import SimlesslyError
from .output import NOT_PROOF, STATUS_MEANING, mask_text, normalize_status, sanitize
from .preview import Look, Preview, Refusal, pluralize, render_preview
from . import portal_cli
from .portal_cli import _client, _read, _resolve_config_named, _stored_token
from .portal_read import ON_PHONE_STATUSES, _need_dict, _need_list, find_profile, recycle_states

# The website's warning texts.
WARN_DELETE = ("Deleting profiles does not mean they are removed from the devices. "
               "Are you sure you want to proceed with the deletion?")
WARN_REGENERATE = ("The selected profiles have one or more of the following issues: 1. The existing status of the "
                   "profiles are in downloaded/installed/enabled/disabled. 2. The Recycled status of profiles are in "
                   "\"AWAITING\". If regeneration may significantly impact the previous profile's functionality. "
                   "Are you sure you want to proceed with the this?")

MAX_UPLOAD_BYTES = 8 << 20
NOTES_MAX, GROUP_NOTE_MAX = 100, 200
_ON_PHONE_TOKENS = ("DOWNLOADED", "INSTALLED", "ENABLE", "DISABLE")     # the website's substring test
_NOT_PROOF_STATES = {"AVAILABLE", "EXPIRED", "CANCELED", "REMOVED"}
_OFF_PHONE_STATES = {"AVAILABLE", "DELETED", "ERROR"}      # pass without --force
_BOOKKEEPING_STATES = {"EXPIRED", "CANCELED", "REMOVED"}   # platform records: re-generate needs --force
_RECYCLE_CLEAR = {"RECYCLED", "INVALID"}
_FALSE_WORDS = {"", "0", "false", "no", "off", "null", "none"}


def _refused(reason: str, **more: Any) -> Refusal:
    return Refusal([reason], **more)


# ------------------------------------------------------------------ the gate

def _profile_rows(context: dict[str, Any], look: Look) -> list[tuple[str, str]]:
    """Target and current state of the profile a command acts on."""
    rows = [("Target", f"ICCID {context.get('iccid')} (portal id {context.get('id')})")]
    state = [f"{label} {context[key]}" for label, key in (("status", "status"), ("configuration", "configuration"),
                                                          ("group", "group")) if context.get(key) not in (None, "")]
    if state:
        rows.append(("Currently", look.sep.join(state)))
    return rows


def portal_mutate(ctx: Ctx, *, path: str, effect: str, cost: str, body: dict[str, Any] | None = None,
                  upload: dict[str, Any] | None = None, notes: list[str] | None = None,
                  context: dict[str, Any] | None = None, check_hint: str, action: str | None = None,
                  rows: list[tuple[str, str]] | None = None, human_notes: list[str] | None = None,
                  then: list[str] | None = None) -> Any:
    """Send a state-changing portal request once, only with --yes; otherwise print the preview and raise DryRun.

    `upload` (generate-ac only) is {"fields": [(name, value)...], "filename", "content"}.
    `action` is one plain sentence and `rows` the specifics for the preview; `notes` feed --json, and the
    preview shows `human_notes` instead when given. `then` lists the follow-up commands."""
    if path not in portal.WRITE_PATHS:
        raise SimlesslyError(f"refusing to call portal path {path}: it is not one of the state-changing portal calls "
                             "this tool implements", kind="config")
    url = portal.build_portal_url(ctx.settings.base_url(), path)
    mask = lambda text: mask_text(text, ctx.redactor, imsi_text=True)   # typed text can look like a code or a key
    notes = [mask(n) for n in (notes or [])]
    effect = mask(effect)
    action = mask(action) if action else None
    if upload is not None:
        digest = hashlib.sha256(upload["content"]).hexdigest()[:16]
        shown: Any = {"fields": [[k, v] for k, v in upload["fields"]],
                      "file": {"name": upload["filename"], "bytes": len(upload["content"]), "sha256_prefix": digest}}
        body_line = ("multipart/form-data: " + ", ".join(f"{k}={v}" for k, v in upload["fields"])
                     + f"; file={upload['filename']} ({len(upload['content'])} bytes, sha256 {digest}...; content not shown)")
        kind = "multipart/form-data"
    else:
        shown = sanitize({k: v for k, v in (body or {}).items() if v is not None}, ctx.redactor, reveal=True)
        body_line = json.dumps(shown, separators=(",", ":"), ensure_ascii=False)
        kind = "application/json"
    method = portal.WRITE_METHODS[path]
    if not ctx.args.yes:
        if ctx.args.json:
            ctx.show_json({"dry_run": True, "method": method, "url": url, "body": shown,
                           "effect": effect, "cost": cost, "notes": notes, **({"profile": context} if context else {})})
            ctx.warn("dry run: nothing was changed. Add --yes to send this request.")
        else:
            look = ctx.look
            preview = Preview(
                action=action or effect[:1].upper() + effect[1:], cost=cost, effect=effect, method=method, url=url,
                rows=[(label, mask(value)) for label, value in
                      [*(_profile_rows(context, look) if context else []), *(rows or [])]],
                body=body_line if upload is None else None,
                notes=[mask(n) for n in human_notes] if human_notes is not None else notes,
                then=list(then or []),
                debug_rows=[("Headers", f"Content-Type: {kind}, plus Simlessly-Token, Simlessly-Timestamp, "
                                        "Simlessly-RequestID and Simlessly-TimeZone added at send time "
                                        "(the token is never shown)"),
                            *([("Raw body", body_line)] if upload is not None else [])])
            ctx.say(render_preview(preview, look, debug=ctx.args.debug))
        raise DryRun
    client = _client(ctx, _stored_token(ctx))
    ctx.check_hint = check_hint
    ctx.mutated = True
    ctx.sent = (method, url, tuple(then or []))
    if upload is not None:
        return client.write_multipart(path, upload["fields"], upload["filename"], upload["content"])
    return client.write(path, body)


def _finish(ctx: Ctx, obj: Any, done: str, extra: dict[str, Any] | None = None) -> int:
    if ctx.args.json:
        ctx.show_json({"success": True, **(extra or {}), **({"result": sanitize(obj, ctx.redactor)} if obj is not None else {})})
    else:
        ctx.confirm(done)
    return 0


# ------------------------------------------------------------------ lookups and checks

def _profile_id(row: dict[str, Any]) -> Any:
    value = row.get("id")
    if isinstance(value, bool) or not isinstance(value, (int, str)) or value == "":
        raise SimlesslyError("the portal's fleet row has no profile id, so the change cannot be addressed; nothing was done",
                             kind="parse")
    return value


def _context(row: dict[str, Any]) -> dict[str, Any]:
    return {"iccid": row.get("iccid"), "id": row.get("id"), "status": row.get("status"),
            "configuration": row.get("configName") or row.get("configurationName"), "group": row.get("groupName")}


def _refuse_demo(row: dict[str, Any], action: str) -> None:
    if str(row.get("createBy") or "").lower() == "demo":
        raise _refused("this is a demo profile (createBy=demo): the website refuses to operate on demo data, "
                       "and so does this tool", action=action)


def _flag(value: Any) -> bool:
    """Truthiness of a vendor flag; an unrecognised non-empty value counts as set."""
    if isinstance(value, str):
        return value.strip().lower() not in _FALSE_WORDS
    return bool(value)


def _refuse_unmanaged(row: dict[str, Any], action: str) -> None:
    """The website hides Delete and Re-generate for campaign and pre-occupied profiles, so they are never sent."""
    flags = [name for name in ("campaignFlag", "preOccupy") if _flag(row.get(name))]
    if flags:
        raise _refused(f"this profile is flagged {' / '.join(flags)} (a campaign or pre-occupied profile): the website "
                       "does not offer this action for it, so it is not sent, even with --force", action=action)


def _recycle_class(value: Any) -> str:
    """'awaiting', 'clear' (known not AWAITING) or 'unknown'. The Fleet filter's integer 0 means AWAITING."""
    if isinstance(value, bool):
        return "unknown"
    if value == 0 or (isinstance(value, str) and value.strip() == "0"):
        return "awaiting"
    token = str(value).strip().upper() if isinstance(value, str) else ""
    if token == "AWAITING":
        return "awaiting"
    return "clear" if token in _RECYCLE_CLEAR else "unknown"


def _recycle_state(ctx: Ctx, row: dict[str, Any], iccid: str) -> tuple[str, str]:
    """(class, description) of this ICCID's recycle state; exactly one row must exist."""
    rows = recycle_states(ctx, [iccid])
    mine = [r for r in rows if isinstance(r, dict) and str(r.get("iccid", "")).strip().upper() == iccid.upper()]
    if len(mine) != 1:
        return "unknown", ("the portal's recycle query returned no row for this ICCID" if not mine
                           else f"the portal's recycle query returned {len(mine)} rows for this ICCID")
    value = mine[0].get("status")
    state = _recycle_class(value)
    if state != "awaiting" and row.get("recycleStatus") not in (None, "") and _recycle_class(row.get("recycleStatus")) == "awaiting":
        return "awaiting", "its fleet row says the recycle state is AWAITING"
    return state, ("recycle state is AWAITING" if state == "awaiting" else
                   f"its recycle state {_shown(value)} is not a recognised one" if state == "unknown" else "")


def _shown(value: Any) -> str:
    return repr(value if isinstance(value, (str, int, float)) else type(value).__name__)[:60]


def _guard_on_phone(ctx: Ctx, row: dict[str, Any], recycle: tuple[str, str] | None, *, action: str,
                    warning: str | None, notes: list[str], mode: str) -> None:
    """Refuse (unless --force) unless the profile is known to be off a phone; appends notes.

    `action` is the sentence the dry run shows in its Action row. `mode` is 'delete', 'regenerate' or 'recycle'. For recycle, being on a phone is expected (the caller
    already required AWAITING), so only a missing or unrecognised status refuses. `recycle` is the
    (class, description) of the ICCID's recycle state, None for 'recycle'."""
    _refuse_demo(row, action)
    if mode != "recycle":
        _refuse_unmanaged(row, action)
    raw = str(row.get("status") or "")
    token = normalize_status(raw)
    reasons: list[str] = []
    website_text = False                      # the website itself warns about these reasons
    if not raw.strip():
        reasons.append("the portal reports no status for it, so it cannot be told whether it is on a phone")
    elif token in ON_PHONE_STATUSES or any(t in raw.upper() for t in _ON_PHONE_TOKENS):
        if mode != "recycle":
            reasons.append(f"its status is {raw}, i.e. the eSIM is on, or possibly on, a phone")
            website_text = True
    elif token in _BOOKKEEPING_STATES:
        if mode == "regenerate":
            reasons.append(f"its status {token} is platform bookkeeping, {NOT_PROOF}")
    elif token in _OFF_PHONE_STATES:
        pass
    elif mode == "recycle" and token in STATUS_MEANING:
        pass
    else:
        reasons.append(f"unrecognised status {raw!r}, so it cannot be told whether it is on a phone")
    if recycle is not None:
        state, why = recycle
        if state == "awaiting":
            reasons.append("its recycle state is AWAITING (the recycle applet is still to remove it from the phone)")
            website_text = True
        elif state == "unknown":
            reasons.append(why)
    if reasons:
        said = (" The website warns: \"" + warning + "\" (--force overrides it).") if website_text and warning else ""
        if not ctx.args.force:
            raise Refusal(reasons, action=action, website=warning if website_text else None,
                          override="if you are sure, repeat with --force (and --yes).")
        notes.append("FORCED (--force): " + "; ".join(reasons) + "." + said)
    if token in _NOT_PROOF_STATES and not (mode == "regenerate" and token in _BOOKKEEPING_STATES):
        notes.append(f"Status {token} is platform bookkeeping, {NOT_PROOF}: the profile may still be installed.")


def _text_arg(value: str, limit: int, what: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or re.search(r"[\x00-\x1f\x7f]", value) or len(value) > limit or (not value and not allow_empty):
        raise UsageError(f"{what} must be {'at most' if allow_empty else '1 to'} {limit} characters without control characters")
    return value


# ------------------------------------------------------------------ metadata: notes, groups

def cmd_portal_notes(ctx: Ctx) -> int:
    a = ctx.args
    iccid = iccid_arg(a.iccid)
    if a.clear and a.text is not None:
        raise UsageError("give the note text or --clear, not both")
    if not a.clear and a.text is None:
        raise UsageError("give the note text, or --clear to empty it")
    text = "" if a.clear else _text_arg(a.text, NOTES_MAX, "the note")
    action = f"{'Clear' if a.clear else 'Replace'} the note on profile {iccid}."
    row = find_profile(ctx, iccid)
    _refuse_demo(row, action)
    notes = [f"Current note: {row.get('notes')!r}."] if row.get("notes") not in (None, "") else []
    obj = portal_mutate(
        ctx, path=portal.PATH_FLEET_UPDATE_NOTES, body={"ids": [_profile_id(row)], "notes": text},
        effect="replaces the profile's note on the platform (metadata only; nothing on a phone changes)",
        cost="no charge documented", notes=notes, context=_context(row),
        check_hint=f"Check with `simlessly portal profile {iccid}`", action=action,
        rows=[("New note", "(empty: the note is cleared)" if a.clear else repr(text))],
        then=[f"simlessly portal profile {iccid}"])
    return _finish(ctx, obj, f"Notes for {iccid} " + ("cleared." if a.clear else "updated."))


def _resolve_group(ctx: Ctx, value: str) -> tuple[Any, str]:
    value = _check(r"[^\x00-\x1f\x7f]{1,128}", value, "--group")
    groups = _need_list(_read(ctx, portal.PATH_GROUP_LIST, {}), "group list")
    by_id = [g for g in groups if str(g.get("id")) == value]
    by_name = [g for g in groups if str(g.get("name", "")).lower() == value.lower()]
    found = by_id or by_name
    if len(found) > 1:
        raise UsageError(f"--group {value!r}: several groups match; pass the group id (see `simlessly portal groups`)")
    if not found or found[0].get("id") in (None, ""):
        known = ", ".join(sorted(str(g.get("name")) for g in groups)[:30]) or "none"
        raise UsageError(f"--group {value!r}: no such group (portal knows: {known})")
    return found[0]["id"], str(found[0].get("name"))


def cmd_portal_group_assign(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    row = find_profile(ctx, iccid)
    group_id, group_name = _resolve_group(ctx, ctx.args.group)
    action = f"Put profile {iccid} into the group {group_name!r}."
    _refuse_demo(row, action)
    obj = portal_mutate(
        ctx, path=portal.PATH_GROUP_BATCH, body={"groupId": group_id, "profileIds": [_profile_id(row)]},
        effect=f"puts the profile into the group {group_name!r} (metadata only; nothing on a phone changes)",
        cost="no charge documented", context=_context(row), check_hint=f"Check with `simlessly portal profile {iccid}`",
        action=action,
        rows=[("Group", f"{group_name} (id {group_id})")], then=[f"simlessly portal profile {iccid}"])
    return _finish(ctx, obj, f"{iccid} is now in group {group_name!r}.")


def cmd_portal_group_create(ctx: Ctx) -> int:
    a = ctx.args
    name = _text_arg(a.name, 100, "the group name")
    note = _text_arg(a.note, GROUP_NOTE_MAX, "--note", allow_empty=True)
    obj = portal_mutate(
        ctx, path=portal.PATH_GROUP_ADD, body={"name": name, "note": note},
        effect=f"creates the profile group {name!r} (metadata only)", cost="no charge documented",
        check_hint="Check with `simlessly portal groups`", action=f"Create the profile group {name!r}.",
        rows=[("Group", name), ("Note", note if note else "(none)")], then=["simlessly portal groups"])
    return _finish(ctx, obj, f"Group {name!r} created.")


# ------------------------------------------------------------------ re-generate, recycle, delete

_FORMAT_NAMES = {"STRING": "activation code text", "PICTURE": "QR picture", "AC_LINK": "activation link"}


def _format_names(formats: list[str]) -> str:
    return ", ".join(f"{_FORMAT_NAMES.get(f, f)} ({f})" for f in formats)


_EXPIRE_RE = re.compile(r"(\d{4})[/-](\d{2})[/-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})")


def _expire_time(value: str) -> str:
    m = _EXPIRE_RE.fullmatch((value or "").strip())
    if not m:
        raise UsageError("--expire-time: expected 'YYYY/MM/DD HH:MM:SS'")
    y, mo, d, h, mi, s = map(int, m.groups())
    try:
        datetime(y, mo, d, h, mi, s)
    except ValueError:
        raise UsageError("--expire-time is not a real date and time") from None
    return f"{y:04d}/{mo:02d}/{d:02d} {h:02d}:{mi:02d}:{s:02d}"


def cmd_portal_regenerate(ctx: Ctx) -> int:
    a = ctx.args
    iccid = iccid_arg(a.iccid)
    expire = _expire_time(a.expire_time) if a.expire_time else None
    action = f"Issue a new activation code for profile {iccid}."
    row = find_profile(ctx, iccid)
    notes: list[str] = []
    _refuse_demo(row, action)
    _refuse_unmanaged(row, action)
    _guard_on_phone(ctx, row, _recycle_state(ctx, row, iccid), action=action,
                    warning=WARN_REGENERATE, notes=notes, mode="regenerate")
    config_id = row.get("configId")
    if isinstance(config_id, bool) or not isinstance(config_id, (int, str)) or config_id == "":
        raise SimlesslyError("the portal's fleet row has no configId, so the configuration to re-generate with is "
                             "unknown; nothing was sent", kind="parse")
    formats = ["STRING"] + (["PICTURE"] if a.picture else [])
    body = {"configId": config_id, "profileIds": [_profile_id(row)], "acFormat": formats, "expireTime": expire}
    if a.picture:
        notes.append("PICTURE is refused by the portal on a BASIC plan (BASIC only offers STRING).")
    if expire:
        notes.append("The expireTime option only applies to Recycle / Custom configurations.")
    human_notes = list(notes) + ["The portal runs this as an asynchronous batch task (type RE_GENERATE); the new code "
                                 "then appears in `simlessly portal profile`."]
    notes.append("The portal runs this as an asynchronous batch task (type RE_GENERATE): follow it with "
                 "`simlessly portal batch-logs --type RE_GENERATE`; the new code is then in `portal profile`.")
    config_name = row.get("configName") or row.get("configurationName")
    obj = portal_mutate(
        ctx, path=portal.PATH_FLEET_RE_GENERATE, body=body,
        effect="issues a new activation code for the profile; the previous code may stop working, and a profile "
               "already on a phone may break",
        cost="BILLABLE: may count as a new download on the plan once the new code is installed",
        notes=notes, context=_context(row), check_hint=f"Check with `simlessly portal profile {iccid}` and `simlessly portal batch-logs`",
        action=action,
        rows=[("Config", f"{config_name} ({config_id})" if config_name else str(config_id)),
              ("Format", _format_names(formats)), *([("Expires", expire)] if expire else [])],
        human_notes=human_notes, then=["simlessly portal batch-logs --type RE_GENERATE", f"simlessly portal profile {iccid}"])
    return _finish(ctx, obj, f"Re-generate submitted for {iccid}. The portal processes it in the background.")


_AT_RE = re.compile(r"(\d{4})[/-](\d{2})[/-](\d{2})[ T](\d{2})(?::00(?::00)?)?")


def _recycle_time(value: str) -> str:
    m = _AT_RE.fullmatch((value or "").strip())
    if not m:
        raise UsageError("--at: expected 'YYYY/MM/DD HH' (a whole hour, e.g. '2026/10/20 14')")
    y, mo, d, h = map(int, m.groups())
    try:
        when = datetime(y, mo, d, h)
    except ValueError:
        raise UsageError("--at is not a real date and hour") from None
    if when <= datetime.now():
        raise UsageError("--at must be in the future (this machine's clock)")
    return f"{y:04d}/{mo:02d}/{d:02d} {h:02d}:00:00"


def cmd_portal_recycle(ctx: Ctx) -> int:
    a = ctx.args
    iccid = iccid_arg(a.iccid)
    when = _recycle_time(a.at)
    action = f"Set the recycle time of profile {iccid} to {when}."
    row = find_profile(ctx, iccid)
    _refuse_demo(row, action)
    state, why = _recycle_state(ctx, row, iccid)
    if normalize_status(row.get("status")) == "AVAILABLE":
        raise _refused("the website only offers a recycle-time change for a profile that is not AVAILABLE", action=action)
    if state != "awaiting":
        raise _refused("the website only offers a recycle-time change while this profile's recycle state is AWAITING "
                       f"({why or 'its recycle state is not AWAITING'}; see `simlessly portal recycle-status`)",
                       action=action)
    notes: list[str] = []
    _guard_on_phone(ctx, row, None, action=action, warning=None, notes=notes, mode="recycle")
    notes.append("The time is sent as typed; the portal's time zone for it is not documented (the website sends the "
                 "date picker's value). Only the 'Other time' form is supported, not 'Now'.")
    obj = portal_mutate(
        ctx, path=portal.PATH_FLEET_RECYCLE, body={"iccid": iccid, "recycleTime": when},
        effect="schedules the recycle applet to remove the profile from the phone at its next connection after that time",
        cost="no charge documented", notes=notes, context=_context(row),
        check_hint=f"Check with `simlessly portal recycle-status {iccid}`",
        action=action, rows=[("Recycle at", when)],
        then=[f"simlessly portal recycle-status {iccid}"])
    return _finish(ctx, obj, f"Recycle time for {iccid} set to {when}.")


def cmd_portal_delete(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    action = f"Delete profile {iccid} from the platform."
    row = find_profile(ctx, iccid)
    notes: list[str] = []
    _refuse_demo(row, action)
    _refuse_unmanaged(row, action)
    _guard_on_phone(ctx, row, _recycle_state(ctx, row, iccid), action=action, warning=WARN_DELETE, notes=notes,
                    mode="delete")
    notes.append("Deleting a profile from the platform does not remove it from a device.")
    obj = portal_mutate(
        ctx, path=portal.PATH_FLEET_DELETE, body={"ids": [_profile_id(row)]},
        effect="deletes the profile from the platform (irreversible; it is not removed from any device)",
        cost="no charge documented", notes=notes, context=_context(row),
        check_hint=f"Check with `simlessly portal profile {iccid}`",
        action=action, then=[f"simlessly portal profile {iccid}"])
    return _finish(ctx, obj, f"Deleted {iccid} from the platform.")


# ------------------------------------------------------------------ generate-ac (file upload)

def cmd_portal_generate_ac(ctx: Ctx) -> int:
    a = ctx.args
    path = a.file
    ext = os.path.splitext(path)[1].lower()
    if a.upload_type == "pgp" and ext != ".gpg":
        raise UsageError("--upload-type pgp expects a PGP-encrypted .gpg file")
    if a.upload_type == "plain" and ext not in (".xls", ".xlsx"):
        raise UsageError("--upload-type plain expects an .xls or .xlsx file")
    try:
        info = os.lstat(path)
    except OSError:
        raise UsageError("--file: cannot read that file") from None
    import stat as _stat
    if not _stat.S_ISREG(info.st_mode):
        raise UsageError("--file must be an ordinary file (not a link or device)")
    if info.st_size == 0 or info.st_size > MAX_UPLOAD_BYTES:
        raise UsageError(f"--file must be between 1 byte and {MAX_UPLOAD_BYTES >> 20} MiB")
    try:
        with open(path, "rb") as handle:
            content = handle.read(MAX_UPLOAD_BYTES + 1)
    except OSError:
        raise UsageError("--file: cannot read that file") from None
    if len(content) > MAX_UPLOAD_BYTES:
        raise UsageError(f"--file must be between 1 byte and {MAX_UPLOAD_BYTES >> 20} MiB")
    filename = os.path.basename(path)
    action = f"Upload {filename} and create profiles from its records."
    config_id, config_name = _resolve_config_named(ctx, a.config)
    plan = _need_dict(_read(ctx, portal.PATH_PLAN_QUERY_ORDER, {}), "subscription")
    ac_count = _need_dict(_read(ctx, portal.PATH_ANALYTIC_AC_COUNT, {}), "AC count").get("acCount")
    plan_type = str(plan.get("planType") or "").strip().upper()
    if plan_type == "DEFAULT" and (isinstance(ac_count, bool) or not isinstance(ac_count, int) or ac_count >= 1):
        raise _refused(f"the free (DEFAULT) plan is limited to 1 profile and this account already has acCount={ac_count!r}: "
                       "the website blocks the upload in that case, so it is not sent", action=action)
    formats = ["STRING"] + (["PICTURE"] if a.picture else []) + (["AC_LINK"] if a.ac_link else [])
    fields = [("configId", str(config_id)), ("uploadType", "1" if a.upload_type == "pgp" else "0")]
    fields += [("acFormats", f) for f in formats]
    look = ctx.look
    notes = [f"Plan check (as the website does): planType={plan.get('planType')!r}, acCount={ac_count!r}.",
             "Creates one profile per record in the file (the portal allows up to 10,000 records per file); "
             "the free (DEFAULT) plan is limited to 1 profile.",
             "The portal runs this as an asynchronous batch task: follow it with `simlessly portal batch-logs`."]
    human_notes = ["Creates one profile per record in the file (the portal allows up to 10,000 records per file); "
                   "the free (DEFAULT) plan is limited to 1 profile.",
                   "The portal runs this as an asynchronous batch task."]
    if a.upload_type == "plain":
        warning = ("WARNING: a plain spreadsheet sends the SIM keys (Ki / OPc) to Simlessly without the PGP layer (only "
                   "TLS protects them); encrypt the file with the portal's PGP key and use --upload-type pgp when you can.")
        notes.append(warning)
        human_notes.append(warning)
    digest = hashlib.sha256(content).hexdigest()
    plan_text = str(plan.get("planType") or "unknown plan")
    generated = (f"{pluralize(ac_count, 'profile')} generated so far"
                 if isinstance(ac_count, int) and not isinstance(ac_count, bool) else "profiles generated: not reported")
    plan_row = look.sep.join([plan_text, generated, "checked as the website does"])
    rows = [("Config", f"{config_name} ({config_id})" if config_name else str(config_id)),
            ("File", look.sep.join([filename, f"{len(content):,} bytes", f"sha256 {digest[:8]}{look.dots}",
                                    "PGP encrypted" if a.upload_type == "pgp" else "plain spreadsheet (no PGP layer)",
                                    "content not shown"])),
            ("Format", _format_names(formats)),
            ("Plan", plan_row)]
    obj = portal_mutate(
        ctx, path=portal.PATH_FLEET_GENERATE_AC, upload={"fields": fields, "filename": os.path.basename(path), "content": content},
        effect="creates profiles (and activation codes) for every record in the uploaded file",
        cost="BILLABLE: creates profiles and uses plan quota; uploads the file's SIM key material",
        notes=notes, check_hint="Check with `simlessly portal batch-logs` and `simlessly portal fleet`",
        action=action, rows=rows, human_notes=human_notes,
        then=["simlessly portal batch-logs", "simlessly portal fleet"])
    return _finish(ctx, obj, "Upload accepted. The portal processes it in the background.")


# ------------------------------------------------------------------ parser

def register(s, leaf) -> None:
    """Add the state-changing commands to the `portal` group."""
    p = leaf(s, "notes", "set a profile's note (dry run unless --yes)", cmd_portal_notes, mutating=True)
    p.add_argument("iccid")
    p.add_argument("text", nargs="?", help=f"the note, up to {NOTES_MAX} characters (replaces the current one)")
    p.add_argument("--clear", action="store_true", help="empty the note")

    p = leaf(s, "group-assign", "put a profile into a group (dry run unless --yes)", cmd_portal_group_assign,
             mutating=True)
    p.add_argument("iccid")
    p.add_argument("--group", required=True, metavar="NAME_OR_ID", help="group name or id (see `portal groups`)")

    p = leaf(s, "group-create", "create a profile group (dry run unless --yes)", cmd_portal_group_create,
             mutating=True)
    p.add_argument("name")
    p.add_argument("--note", default="", help=f"group note, up to {GROUP_NOTE_MAX} characters")

    force_help = ("proceed although the profile is or may be on a phone, or its status or recycle state is "
                  "unrecognised; the website's warning is printed. Never overrides demo, campaign or "
                  "pre-occupied profiles")
    p = leaf(s, "regenerate", "issue a new activation code (BILLABLE; dry run unless --yes)",
             cmd_portal_regenerate, mutating=True)
    p.add_argument("iccid")
    p.add_argument("--picture", action="store_true", help="also ask for the QR picture format (not on BASIC plans)")
    p.add_argument("--expire-time", metavar="'YYYY/MM/DD HH:MM:SS'", help="only for Recycle / Custom configurations")
    p.add_argument("--force", action="store_true", help=force_help)

    p = leaf(s, "recycle", "set when the recycle applet removes a profile from its phone (dry run unless --yes)",
             cmd_portal_recycle, mutating=True)
    p.add_argument("iccid")
    p.add_argument("--at", required=True, metavar="'YYYY/MM/DD HH'", help="a future whole hour")
    p.add_argument("--force", action="store_true", help=force_help)

    p = leaf(s, "delete", "delete a profile from the platform (dry run unless --yes)", cmd_portal_delete,
             mutating=True)
    p.add_argument("iccid")
    p.add_argument("--force", action="store_true", help=force_help)

    p = leaf(s, "generate-ac", "create profiles from a .gpg, .xls or .xlsx file (BILLABLE; dry run unless --yes)",
             cmd_portal_generate_ac, mutating=True)
    p.add_argument("--config", required=True, metavar="NAME_OR_ID", help="configuration name or configId")
    p.add_argument("--file", required=True, metavar="FILE", help="records file: .gpg, .xls or .xlsx")
    p.add_argument("--upload-type", required=True, choices=("pgp", "plain"),
                   help="pgp: file encrypted with the portal's key (recommended); plain: unencrypted spreadsheet")
    p.add_argument("--picture", action="store_true", help="also produce QR pictures (not on BASIC plans)")
    p.add_argument("--ac-link", action="store_true", help="also produce AC links (not on BASIC plans)")
