"""`simlessly portal ...`: commands that use the web portal's session API.

This module holds what every portal command shares (session token, paging, masking, CSV) and the
session, fleet and log commands. Other read-only commands are in portal_read.py; state-changing ones
are in portal_write.py, the only module that reaches a state-changing portal path, behind the same
preview / --yes / no-retry gate as the RSP commands. `register()` adds the commands to the main parser.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from . import portal, store as stores
from .cli import (
    EXIT_FAIL, EXIT_OK, Ctx, UsageError, _backends, _bounded_number, _check, _pick, _read_setting_value, _warn_if_shadowed,
    page_arg,
)
from .client import SimlesslyError
from .config import ConfigError
from .output import AC_KEYS, clean, kv, normalize_status, sanitize, status_meaning, table
from .portal import PortalClient, PortalSessionExpired

PORTAL_TOKEN = "portal-token"
MAX_PAGES = 100            # page cap for `--all`
PAGE_PAUSE = 0.5           # seconds between pages
DEFAULT_PAGE_SIZE = 50
page_size_arg = _bounded_number("page-size", 1, 200, integer=True)

STATUS_CAVEAT = ("Portal data. The statuses AVAILABLE, EXPIRED, CANCELED and REMOVED are platform "
                 "records, not proof an eSIM left a phone.")
FLEET_COLUMNS = ["iccid", "status", "config", "msisdn", "eid", "imsi", "activation code", "created", "updated"]


def _pause(seconds: float) -> None:
    time.sleep(seconds)    # a function so tests can replace it


# ------------------------------------------------------------------ plumbing

def _client(ctx: Ctx, token: str | None) -> PortalClient:
    debug = (lambda line: ctx.err.write("debug: " + line + "\n")) if ctx.args.debug else None
    tz = portal.local_timezone({"TZ": ctx.settings.env_value("TZ") or ""})
    return PortalClient(ctx.settings.base_url(), token, timezone=tz, timeout=ctx.args.timeout,
                        redactor=ctx.redactor, debug=debug)


_NO_SESSION = ("no portal session stored: run `simlessly portal login` "
               "(or `simlessly portal token-set` for an SSO account)")


def _stored_token(ctx: Ctx) -> str:
    value = ctx.settings.get(PORTAL_TOKEN).value        # ConfigError if the credentials file is refused
    if not value:
        raise ConfigError(_NO_SESSION)
    if re.search(r"[\x00-\x1f\x7f]", value) or not value.isascii():
        raise ConfigError("the stored portal token contains characters that cannot be sent "
                          "(re-enter it with `simlessly portal token-set`)")
    ctx.redactor.add(value)
    return value


def _read(ctx: Ctx, path: str, data: dict[str, Any] | None = None) -> Any:
    """One read-only portal call. `data` is the JSON body or the query parameters, per portal.READ_METHODS."""
    return _client(ctx, _stored_token(ctx)).read(path, data)


def _store_token(ctx: Ctx, token: str) -> str:
    ctx.redactor.add(token)
    try:
        where = _backends(ctx).store(ctx.args.store, PORTAL_TOKEN, token)
    except stores.StoreError as err:
        raise ConfigError(f"could not store the portal session: {ctx.redactor.scrub(str(err))}") from None
    _warn_if_shadowed(ctx, PORTAL_TOKEN, where)
    return where


def _is_tty(ctx: Ctx) -> bool:
    return bool(getattr(ctx.stdin, "isatty", lambda: False)())


# ------------------------------------------------------------------ login / token-set / logout

def _email(ctx: Ctx) -> str:
    email = ctx.args.email
    if email is None:
        if not _is_tty(ctx):
            raise UsageError("stdin is not a terminal, so the e-mail address cannot be prompted for; "
                             "pass --email")
        ctx.err.write("Simlessly e-mail address: ")
        ctx.err.flush()
        email = ctx.stdin.readline().rstrip("\r\n")
    email = email.strip()
    if not re.fullmatch(r"[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+", email) or len(email) > 254:
        raise UsageError("e-mail address looks wrong")
    return email


def _password(ctx: Ctx) -> str:
    if ctx.args.password_stdin:
        if _is_tty(ctx):
            raise UsageError("--password-stdin expects piped input (typing it here would show the password on "
                             "screen); omit the flag to use the hidden prompt")
        password = ctx.stdin.readline().rstrip("\r\n")
    elif _is_tty(ctx):
        password = getpass.getpass("Simlessly password (input hidden): ", stream=ctx.err)
    else:
        raise UsageError("stdin is not a terminal, so the password cannot be prompted for; "
                         "run this in a terminal, or pipe it in with --password-stdin. "
                         "The password is not accepted as an argument or from the environment.")
    if not password:
        raise UsageError("the password is empty")
    return password


def cmd_portal_login(ctx: Ctx) -> int:
    email = _email(ctx)
    password = _password(ctx)
    digest = portal.md5_hex(password)
    del password                                           # only until hashed
    ctx.redactor.add(email, digest)                        # the only login values that are sent
    body = {"email": email, "password": digest, "activeToken": "", "sys": "rsp"}
    obj = _client(ctx, None).session(portal.PATH_LOGIN, body)
    token = obj.get("token") if isinstance(obj, dict) else None
    if not isinstance(token, str) or not token.strip():
        raise SimlesslyError("the portal accepted the login but returned no readable session token", kind="parse")
    try:
        token = stores.clean_value(token, ascii_only=True)
    except stores.StoreError:
        raise SimlesslyError("the portal returned a session token that cannot be stored safely", kind="parse") from None
    where = _store_token(ctx, token)
    if ctx.args.json:
        ctx.show_json({"signed_in": True, "stored_in": where})
    else:
        ctx.say(f"signed in; session stored in {where}")
    if isinstance(obj, dict) and (obj.get("isFirstLogin") is True or obj.get("isRegister") is True):
        ctx.warn("note: the portal flags this as a first login or new registration. Complete any "
                 "first-login steps in the browser.")
    return EXIT_OK


def cmd_portal_token_set(ctx: Ctx) -> int:
    if ctx.args.from_stdin:
        if _is_tty(ctx):
            raise UsageError("--from-stdin expects piped input (typing it here would show the value on "
                             "screen); omit the flag to use the hidden prompt")
        raw = ctx.stdin.readline().rstrip("\r\n")
    elif _is_tty(ctx):
        raw = getpass.getpass("simlessly_token cookie value (input hidden): ", stream=ctx.err)
    else:
        raise UsageError("stdin is not a terminal, so the value cannot be prompted for; "
                         "run this in a terminal, or pipe the value in with --from-stdin")
    raw = raw.strip()
    if raw.lower().startswith("simlessly_token="):          # accept a pasted "name=value" cookie
        raw = raw.split("=", 1)[1].strip()
    raw = raw.rstrip(";").strip()
    try:
        token = stores.clean_value(raw, ascii_only=True)
    except stores.StoreError as err:
        raise ConfigError(f"{PORTAL_TOKEN}: {err}") from None
    where = _store_token(ctx, token)
    if ctx.args.json:
        ctx.show_json({"stored_in": where})
    else:
        ctx.say(f"session token stored in {where}")
    return EXIT_OK


def _end_portal_session(ctx: Ctx, token: str | None) -> None:
    """Ask the portal to end this session. Best effort; never raises."""
    if not token or re.search(r"[\x00-\x1f\x7f]", token) or not token.isascii():
        return
    ctx.redactor.add(token)
    try:
        _client(ctx, token).session(portal.PATH_LOGOUT)
    except PortalSessionExpired:
        pass                                                # already ended on the portal side
    except SimlesslyError as err:                           # best effort: still remove the local copy
        ctx.warn(f"note: the portal did not confirm the logout ({ctx.redactor.scrub(str(err))}); "
                 "the session may stay valid until it expires.")


_STORED_SOURCES = ("keychain", "secret-service", "file")


def cmd_portal_logout(ctx: Ctx) -> int:
    setting = ctx.settings.get(PORTAL_TOKEN)
    _end_portal_session(ctx, setting.value)
    choice = ctx.args.store
    auto = choice == "auto"
    if auto and setting.source in _STORED_SOURCES:
        choice = setting.source                             # remove from where it was found
    try:
        where, removed = _backends(ctx).delete(choice, PORTAL_TOKEN)
    except stores.StoreError as err:
        raise ConfigError(f"could not remove {PORTAL_TOKEN}: {err}") from None
    ctx.say(f"signed out; removed the stored session from {where}" if removed
            else f"signed out; no stored session was found in {where}")
    # A lower-priority store may hold a copy the next command would use.
    seen = {setting.value} if setting.value else set()
    for _ in range(len(_STORED_SOURCES)):
        try:
            rest = ctx.settings.fresh().get(PORTAL_TOKEN)
        except ConfigError:
            break
        if rest.source not in _STORED_SOURCES or not rest.value:
            break
        hint = f"`simlessly config unset {PORTAL_TOKEN} --store {rest.source}`"
        if not auto:
            ctx.warn(f"note: another stored session remains in {rest.source}; remove it with {hint}.")
            break
        if rest.value not in seen:
            _end_portal_session(ctx, rest.value)
            seen.add(rest.value)
        try:
            where2, removed2 = _backends(ctx).delete(rest.source, PORTAL_TOKEN)
        except stores.StoreError as err:
            ctx.warn(f"note: another stored session remains in {rest.source} and could not be removed "
                     f"({ctx.redactor.scrub(str(err))}); run {hint}.")
            break
        if not removed2:
            ctx.warn(f"note: another stored session remains in {rest.source}; remove it with {hint}.")
            break
        ctx.say(f"also removed a second stored session from {where2}")
    if setting.source == "env":
        ctx.warn("note: SIMLESSLY_PORTAL_TOKEN is set in the environment; unset it there.")
    return EXIT_OK


# ------------------------------------------------------------------ fleet / logs

def _page_rows(obj: Any, what: str) -> list[dict[str, Any]]:
    if not isinstance(obj, dict):
        raise SimlesslyError(f"unexpected answer shape for {what}", kind="parse")
    rows = obj.get("pageData")
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise SimlesslyError(f"unexpected answer shape for {what} (no pageData list)", kind="parse")
    return rows


def _total(obj: Any) -> int | None:
    """The reported total: obj.pageParam.total, then obj.total."""
    if not isinstance(obj, dict):
        return None
    page_param = obj.get("pageParam")
    candidates = [page_param.get("total") if isinstance(page_param, dict) else None, obj.get("total")]
    for value in candidates:
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return None


def _when(value: Any) -> str:
    """Epoch milliseconds become ISO-8601 UTC; anything else is shown as sent."""
    text = "" if value is None else str(value).strip()
    if re.fullmatch(r"\d{12,13}", text):
        try:
            return datetime.fromtimestamp(int(text) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            return text
    return text


def _parse_when(text: str, flag: str, *, end: bool) -> str:
    """--since/--until: YYYY-MM-DD (local; --until means the end of that day) or an ISO-8601 time.
    Returns epoch milliseconds as a string."""
    text = text.strip()
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise UsageError(f"{flag}: expected YYYY-MM-DD or an ISO-8601 time") from None
    if end and re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        moment = moment.replace(hour=23, minute=59, second=59, microsecond=999000)
    try:
        moment = moment.astimezone()                        # a time without an offset means this machine's zone
        return str(int(moment.timestamp() * 1000))
    except (OverflowError, OSError, ValueError):
        raise UsageError(f"{flag}: that time is out of range") from None


_CONFIG_NAME_KEYS = ("configName", "name", "label", "text")
_CONFIG_ID_KEYS = ("configId", "id", "value", "key")


def _scalar_id(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)) or value == "":
        return None
    return str(value)


def _config_items(obj: Any, nested: bool = False):
    """(display name, [string fields], configId or None) per config option.

    The item shape is unverified, so accept {label,value}, {name,id}, {configName,configId} and plain
    strings (their own id), in a list or a wrapper object."""
    if isinstance(obj, str):
        if obj.strip():
            yield obj, [obj], obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _config_items(item, True)
    elif isinstance(obj, dict):
        item_id = next((i for i in (_scalar_id(obj.get(k)) for k in _CONFIG_ID_KEYS) if i is not None), None)
        strings = [v for v in obj.values() if isinstance(v, str) and v.strip()]
        if strings and (nested or item_id is not None):
            name = next((obj[k] for k in _CONFIG_NAME_KEYS if isinstance(obj.get(k), str) and obj[k].strip()), strings[0])
            yield name, strings, item_id
        else:
            for value in obj.values():
                if isinstance(value, (list, dict)):
                    yield from _config_items(value)


_CONFIG_ID_RE = re.compile(r"\d+|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")


def _resolve_config(ctx: Ctx, value: str) -> str:
    """--config as a configId (see _resolve_config_named)."""
    return _resolve_config_named(ctx, value)[0]


def _resolve_config_named(ctx: Ctx, value: str) -> tuple[str, str | None]:
    """--config as (configId, name). A number or UUID is the id, with no name (no extra lookup is made);
    anything else is a name, looked up with one config/name/query call and matched case-insensitively
    against any string field."""
    value = _check(r"[^\x00-\x1f\x7f]{1,128}", value, "--config")
    if _CONFIG_ID_RE.fullmatch(value):
        return value, None
    obj = _read(ctx, portal.PATH_CONFIG_NAME_QUERY, {"filterDemo": False})
    items = list(_config_items(obj))
    if not items:
        raise SimlesslyError("could not read the portal's configuration list; pass the configId "
                             "(a number) to --config instead of a name", kind="parse")
    wanted = value.lower()
    ids = sorted({i for _, strings, i in items if i is not None and any(s.lower() == wanted for s in strings)})
    if len(ids) == 1:
        shown = next((clean(n, 80) for n, strings, i in items if i == ids[0] and any(x.lower() == wanted for x in strings)), value)
        return ids[0], shown
    if ids:
        raise UsageError(f"--config {value!r}: several configurations have that name; pass the configId")
    if any(any(s.lower() == wanted for s in strings) for _, strings, _ in items):
        raise SimlesslyError("the portal's configuration list has that name but no configId; "
                             "pass the configId (a number) to --config instead", kind="parse")
    names = ", ".join(sorted({clean(n, 80) for n, _, _ in items})[:30])
    raise UsageError(f"--config {value!r}: no configuration with that name (portal knows: {names})")


def _fleet_body(ctx: Ctx, page: int, page_size: int, filters: dict[str, str]) -> dict[str, Any]:
    return {"iccid": filters["iccid"], "iccidList": "", "status": filters["status"], "configId": filters["configId"],
            "startTime": filters["startTime"], "endTime": filters["endTime"], "groupId": "", "recycleStatus": "",
            "acString": "", "msisdn": filters["msisdn"], "pageParam": {"pageNum": page, "pageSize": page_size}}


def _fleet_filters(ctx: Ctx) -> dict[str, str]:
    a = ctx.args
    filters = {
        "iccid": _check(r"\d{1,20}", a.iccid, "--iccid (digits, full or partial)") if a.iccid else "",
        "status": _check(r"[A-Za-z0-9_ -]{1,32}", a.status, "--status") if a.status else "",
        "msisdn": _check(r"\+?\d{1,15}", a.msisdn, "--msisdn (expected up to 15 digits)") if a.msisdn else "",
        "startTime": _parse_when(a.since, "--since", end=False) if a.since else "",
        "endTime": _parse_when(a.until, "--until", end=True) if a.until else "",
        "configId": "",
    }
    if filters["startTime"] and filters["endTime"] and int(filters["startTime"]) > int(filters["endTime"]):
        raise UsageError("--since is after --until")
    return filters


def _row_key(row: dict[str, Any]) -> str:
    """Identity of a fleet row (one per ICCID)."""
    iccid = row.get("iccid")
    return str(iccid) if iccid not in (None, "") else _event_key(row)


def _event_key(row: dict[str, Any]) -> str:
    """Identity of any other row: the whole row (log entries share an ICCID)."""
    return repr(sorted(row.items(), key=lambda kv_: kv_[0]))


# Why an `--all` walk stopped.
STOP_TOTAL, STOP_EMPTY = "total-reached", "empty-page"
STOP_CAP, STOP_REPEAT, STOP_SHORT = "page-cap", "repeated-rows", "short-of-total"


def _fetch_pages(ctx: Ctx, path: str, make_body, what: str, *, page_size: int, page: int | None,
                 walk_all: bool, key=None) -> tuple[dict[str, Any], list[dict[str, Any]], int | None, int, str | None]:
    """(answer, rows, total, pages fetched, stop reason) for one page, or every page with walk_all.

    `make_body(page_number)` builds the body or query for one page. Without a reported total only an
    empty page ends the walk (a short page may just mean the portal capped pageSize)."""
    key = key or _event_key
    if not walk_all:
        obj = _read(ctx, path, make_body(page or 1))
        rows = _page_rows(obj, what)
        return obj, rows, _total(obj), 1, None
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    first: dict[str, Any] | None = None
    total: int | None = None
    pages, stop = 0, STOP_CAP
    for number in range(1, MAX_PAGES + 1):
        if number > 1:
            _pause(PAGE_PAUSE)
        obj = _read(ctx, path, make_body(number))
        batch = _page_rows(obj, what)
        pages += 1
        if first is None:
            first = obj
        total = _total(obj) if _total(obj) is not None else total
        if not batch:
            stop = STOP_EMPTY
            break
        fresh = [r for r in batch if key(r) not in seen]
        seen.update(key(r) for r in fresh)
        rows.extend(fresh)
        if not fresh:
            ctx.warn("warning: the portal returned the same rows again; stopping (it may ignore the page number)")
            stop = STOP_REPEAT
            break
        if total is not None and len(rows) >= total:
            stop = STOP_TOTAL
            break
    if stop == STOP_EMPTY and total is not None and len(rows) < total:
        stop = STOP_SHORT
    assert first is not None
    return first, rows, total, pages, stop


def _fetch_fleet(ctx: Ctx, filters: dict[str, str]) -> tuple[dict[str, Any], list[dict[str, Any]], int | None, int, str | None]:
    a = ctx.args
    return _fetch_pages(ctx, portal.PATH_FLEET_LIST, lambda n: _fleet_body(ctx, n, a.page_size, filters), "fleet list",
                        page_size=a.page_size, page=a.page, walk_all=a.all, key=_row_key)


def _completeness(stop: str | None, rows: list, total: int | None) -> tuple[bool | None, bool]:
    """(complete, truncated) for an --all walk. complete is None without a total to confirm it;
    truncated means rows were or may have been left out."""
    if stop is None:
        return None, False
    if stop in (STOP_CAP, STOP_REPEAT, STOP_SHORT):
        return False, True
    if total is not None and len(rows) != total:
        return False, False                                 # more rows than the total: reported, not "cut"
    return (True if total is not None else None), False


def _paging_warnings(ctx: Ctx, walk_all: bool, rows: list, total: int | None, stop: str | None, narrow: str) -> None:
    """Completeness messages for `--all` listings (stderr)."""
    if stop == STOP_CAP:
        ctx.warn(f"warning: stopped at the {MAX_PAGES}-page cap with more rows reported; narrow the filters "
                 f"({narrow}) to see the rest.")
    elif walk_all and total is not None and len(rows) != total:
        ctx.warn(f"warning: collected {len(rows)} rows but the portal reports a total of {total}"
                 + ("; this list is not complete." if len(rows) < total else "."))
    elif walk_all and stop == STOP_REPEAT:
        ctx.warn(f"warning: collected {len(rows)} rows; this list may not be complete.")
    if walk_all and total is None:
        ctx.warn("note: the portal reported no total, so completeness could not be checked"
                 + (" (stopped at the first empty page)." if stop == STOP_EMPTY else "."))


def _paging_facts(pages: int, stop: str | None, rows: list, total: int | None) -> dict[str, Any]:
    complete, truncated = _completeness(stop, rows, total)
    return {"pagesFetched": pages, "truncated": truncated, "complete": complete, "stopReason": stop}


def _rows_view(rows: list[dict[str, Any]], ctx: Ctx, reveal_ac: bool) -> list[dict[str, Any]]:
    """Masked row copies. --reveal-ac restores only activation-code fields."""
    view = sanitize(rows, ctx.redactor, imsi_text=True)
    if reveal_ac:
        for shown, raw in zip(view, rows):
            for key, value in raw.items():
                if key.lower() in AC_KEYS and isinstance(value, (str, int)) and value != "":
                    shown[key] = str(value)
    return view


def _fleet_cells(row: dict[str, Any]) -> list[str]:
    config = _pick(row, "configName", "configurationName", "config")
    if config in (None, ""):
        config = row.get("configId")
    return [clean(v) for v in (
        row.get("iccid"), row.get("status"), config, row.get("msisdn"), row.get("eid"), row.get("imsi"),
        _pick(row, "acString", "ac", "activationCode"), _when(row.get("createTime")), _when(row.get("updateTime")),
    )]


_FORMULA_SAFE = re.compile(r"^[+-]?\d[\d .-]*$")


def _csv_cell(text: str) -> str:
    """Stop a spreadsheet treating vendor text as a formula (=, @, or +/- that is not a number)."""
    if text[:1] in ("=", "@", "+", "-") and not _FORMULA_SAFE.match(text):
        return "'" + text
    return text


def _write_csv(path: str, header: list[str], rows: list[list[str]]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)                         # tighten an existing file first
            with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
                fd = -1
                writer = csv.writer(handle)
                writer.writerow(header)
                writer.writerows([[_csv_cell(c) for c in row] for row in rows])
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError as err:
        raise ConfigError(f"could not write {path} ({type(err).__name__})") from None


def cmd_portal_fleet(ctx: Ctx) -> int:
    a = ctx.args
    if a.all and a.page is not None:
        raise UsageError("--all fetches every page; do not combine it with --page")
    filters = _fleet_filters(ctx)
    csv_path = a.csv
    if a.config:
        filters["configId"] = _resolve_config(ctx, a.config)
    obj, rows, total, pages, stop = _fetch_fleet(ctx, filters)
    complete, truncated = _completeness(stop, rows, total)
    reveal = a.reveal_ac
    view = _rows_view(rows, ctx, reveal)
    _paging_warnings(ctx, a.all, rows, total, stop, "--status, --since, --until, --config")
    facts = _paging_facts(pages, stop, rows, total)
    if csv_path:
        cells = [_fleet_cells(r) for r in view]
        _write_csv(csv_path, FLEET_COLUMNS + ["status meaning"],
                   [c + [status_meaning(r.get("status"))] for c, r in zip(cells, view)])
        if a.json:
            ctx.show_json({"csv": csv_path, "rows": len(rows), "total": total, "pages": pages,
                           "truncated": truncated, "complete": complete, "stopReason": stop})
        else:
            ctx.say(f"wrote {len(rows)} profiles to {csv_path} (mode 0600; EID/IMSI masked"
                    + ("" if reveal else ", activation codes masked") + ")")
    elif a.json:
        result = sanitize(obj, ctx.redactor, imsi_text=True)
        if a.all:
            result["pageData"] = view
            result.update(facts)
        else:
            result["pageData"] = view
        ctx.show_json(result)
    else:
        if view:
            ctx.say(table(FLEET_COLUMNS, [_fleet_cells(r) for r in view]))
            statuses = sorted({normalize_status(r.get("status")) for r in view if r.get("status") not in (None, "")})
            if statuses:
                ctx.say("\nStatus meanings:")
                ctx.say(kv([(s, status_meaning(s)) for s in statuses]))
        else:
            ctx.say("No profiles found.")
        shown = f"\n{len(rows)} profiles shown" + (f" of {total}" if total is not None else "")
        if a.all:
            shown += f" ({pages} page{'s' if pages != 1 else ''} fetched)"
        elif total is not None and len(rows) < total:
            shown += "; use --page, or --all to fetch every page"
        ctx.say(shown + ".")
        ctx.say(STATUS_CAVEAT)
    if reveal:
        ctx.warn("warning: activation codes are bearer secrets. Anyone with one can install that eSIM.")
    if a.strict and a.all and complete is False:
        ctx.warn("error: --strict: the list is known to be incomplete (see the warning above).")
        return EXIT_FAIL
    return EXIT_OK


def _log_body(ctx: Ctx, page: int) -> dict[str, Any]:
    a = ctx.args
    iccid = _check(r"\d{1,20}", a.iccid, "--iccid (digits, full or partial)") if a.iccid else ""
    status = _check(r"[A-Za-z0-9_ -]{1,32}", a.status, "--status") if a.status else ""
    start = _parse_when(a.since, "--since", end=False) if a.since else ""
    end = _parse_when(a.until, "--until", end=True) if a.until else ""
    if start and end and int(start) > int(end):
        raise UsageError("--since is after --until")
    # The body the portal's Logs page sends. An unset filter is an empty string.
    return {"iccid": iccid, "status": status, "startTime": start, "endTime": end,
            "pageParam": {"pageNum": page, "pageSize": a.page_size}}


def cmd_portal_logs(ctx: Ctx) -> int:
    a = ctx.args
    if a.all and a.page is not None:
        raise UsageError("--all fetches every page; do not combine it with --page")
    _log_body(ctx, 1)                                       # validate the filters before any call
    obj, rows, total, pages, stop = _fetch_pages(
        ctx, portal.PATH_LOG_PROFILE_LIST, lambda n: _log_body(ctx, n), "profile log list",
        page_size=a.page_size, page=a.page, walk_all=a.all)
    _paging_warnings(ctx, a.all, rows, total, stop, "--iccid, --status, --since, --until")
    view = sanitize(rows, ctx.redactor, imsi_text=True)
    if a.json:
        result = sanitize(obj, ctx.redactor, imsi_text=True)
        result["pageData"] = view
        if a.all:
            result.update(_paging_facts(pages, stop, rows, total))
        ctx.show_json(result)
    else:
        if view:
            ctx.say(table(["time", "iccid", "event", "reason", "operator", "eid", "log id"],
                          [(_when(_pick(r, "createTime", "time")), r.get("iccid"), _pick(r, "status", "event", "type"),
                            clean(_pick(r, "reason", "remark", "message"), 60), r.get("operator"), r.get("eid"),
                            r.get("id")) for r in view]))
        else:
            ctx.say("No log entries.")
        ctx.say(f"\n{len(rows)} entries shown" + (f" of {total}" if total is not None else "")
                + ("" if a.all or total is None or len(rows) >= total else " (use --page to read further pages, or --all)") + ".")
        ctx.say("Portal data; times are as the portal formats them, not sorted here. "
                "`simlessly portal log-detail <log id>` shows the device behind a DOWNLOADED/INSTALLED/ENABLED/DISABLED row.")
    if a.strict and a.all and _completeness(stop, rows, total)[0] is False:
        ctx.warn("error: --strict: the list is known to be incomplete (see the warning above).")
        return EXIT_FAIL
    return EXIT_OK


# ------------------------------------------------------------------ parser

def _refuse_password(_value: str) -> str:
    raise argparse.ArgumentTypeError("the password is not accepted as an argument (it would be saved in shell "
                                     "history); use the hidden prompt or --password-stdin")


def register(group, leaf) -> None:
    """Add the `portal` command group to the root parser."""
    store_help = ("where to store the session: auto (Keychain on macOS, Secret Service on Linux if secret-tool "
                  "works, else the file), keychain, secret-service or file")
    s = group("portal", "the web portal's session API: list and inspect profiles, make guarded changes")

    p = leaf(s, "login", "sign in with e-mail and password and store the portal session",
             cmd_portal_login)
    p.add_argument("--email", help="login e-mail (prompted for on a terminal if omitted)")
    p.add_argument("--password-stdin", action="store_true",
                   help="read the password as one line from stdin")
    p.add_argument("--password", type=_refuse_password, help=argparse.SUPPRESS)   # rejected without echoing
    p.add_argument("--store", choices=stores.STORES, default="auto", help=store_help)

    p = leaf(s, "token-set", "store a simlessly_token cookie copied from the browser (for SSO accounts)",
             cmd_portal_token_set)
    p.add_argument("--from-stdin", action="store_true", help="read the cookie value as one line from stdin")
    p.add_argument("--store", choices=stores.STORES, default="auto", help=store_help)

    p = leaf(s, "logout", "end the portal session (best effort) and remove the stored token", cmd_portal_logout)
    p.add_argument("--store", choices=stores.STORES, default="auto",
                   help="remove from this store (default auto: where the token was found)")

    p = leaf(s, "fleet", "list profiles, like the portal's Profile > Fleet page",
             cmd_portal_fleet)
    p.add_argument("--config", metavar="NAME_OR_ID", help="only this configuration (name or configId)")
    p.add_argument("--status", help="only this status, sent as given")
    p.add_argument("--iccid", help="only this ICCID (digits; full or partial)")
    p.add_argument("--msisdn", help="only this MSISDN")
    p.add_argument("--since", metavar="DATE", help="created on or after: YYYY-MM-DD (local) or an ISO-8601 time")
    p.add_argument("--until", metavar="DATE", help="created on or before: YYYY-MM-DD (end of day) or an ISO-8601 time")
    add_paging(p)
    p.add_argument("--csv", metavar="FILE", help="write the (masked) rows to FILE as CSV, mode 0600")
    p.add_argument("--reveal-ac", action="store_true", help="show activation codes in full")

    p = leaf(s, "logs", "list profile events, like the portal's Logs > Profile page", cmd_portal_logs)
    p.add_argument("--iccid", help="only this ICCID (digits; full or partial)")
    p.add_argument("--status", help="only this event status, sent as given")
    p.add_argument("--since", metavar="DATE", help="on or after: YYYY-MM-DD (local) or an ISO-8601 time")
    p.add_argument("--until", metavar="DATE", help="on or before: YYYY-MM-DD (end of day) or an ISO-8601 time")
    add_paging(p)

    from . import portal_read, portal_write
    portal_read.register(s, leaf)
    portal_write.register(s, leaf)


def add_paging(p, *, strict: bool = True) -> None:
    """Paging options shared by portal lists."""
    p.add_argument("--page", type=page_arg, default=None, help="page number, 1-10000 (default 1)")
    p.add_argument("--page-size", type=page_size_arg, default=DEFAULT_PAGE_SIZE,
                   help=f"rows per page, 1-200 (default {DEFAULT_PAGE_SIZE})")
    p.add_argument("--all", action="store_true",
                   help=f"fetch every page ({PAGE_PAUSE:g}s pause between pages, at most {MAX_PAGES} pages)")
    if strict:
        p.add_argument("--strict", action="store_true",
                       help="with --all: exit 1 when the list is known to be incomplete")
