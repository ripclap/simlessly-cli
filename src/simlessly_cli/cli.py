"""Command-line interface: argument parsing, the safety gate and the RSP API commands.

  main()          wires settings, parses arguments, maps errors to exit codes
  build_parser()  the command tree
  mutate()        the gate every state-changing RSP command goes through

Exit codes
  0  success
  1  failure: bad settings, HTTP error, or refused request
  2  usage error, or a dry run (no --yes)
  3  outcome unknown: a state-changing call timed out, dropped or got an unreadable answer
"""

from __future__ import annotations

import argparse
import math
import getpass
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, TextIO

from . import __version__, client as api
from .client import Client, SimlesslyError
from . import store as stores
from .config import (
    ENV_VARS, REQUIRED, SECRET_SETTINGS, ConfigError, KeychainLookup, Settings, keychain_lookup, validate_base_url,
)
from .output import (
    Redactor, clean, dumps, kv, mask_tail, normalize_status, sanitize, status_meaning, table,
)

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_UNKNOWN = 0, 1, 2, 3
ENV_SIM_KI = "SIMLESSLY_SIM_KI"
ENV_SIM_OPC = "SIMLESSLY_SIM_OPC"


class UsageError(Exception):
    """Bad command-line input. Exit code 2."""

    def __init__(self, message: str, usage: str = "") -> None:
        super().__init__(message)
        self.usage = usage


class DryRun(Exception):
    """Raised by mutate() when --yes was not given. Exit code 2."""


# ------------------------------------------------------------------ context

@dataclass
class Ctx:
    """Everything a command needs."""

    args: argparse.Namespace
    settings: Settings
    redactor: Redactor
    out: TextIO
    err: TextIO
    stdin: TextIO
    backends: "stores.Backends | None" = None
    mutated: bool = False  # set once a state-changing request is sent
    # Advice after an unknown outcome. The portal write commands replace it.
    check_hint: str = "Check the profile with `simlessly profile show <iccid>`"

    def say(self, text: str = "") -> None:
        self.out.write(text + "\n")

    def warn(self, text: str) -> None:
        self.err.write(text + "\n")

    def show_json(self, value: Any) -> None:
        self.say(dumps(value))

    def client(self) -> Client:
        access, secret = self.settings.require("access-key"), self.settings.require("secret-key")
        debug = (lambda line: self.err.write("debug: " + line + "\n")) if self.args.debug else None
        return Client(self.settings.base_url(), access, secret,
                      timeout=self.args.timeout, redactor=self.redactor, debug=debug)

    def read_only(self, path: str, body: dict[str, Any]) -> Any:
        return self.client().post(path, body)


# ------------------------------------------------------------------ input checks

def _check(pattern: str, value: str | None, what: str) -> str:
    value = (value or "").strip()  # the vendor's examples contain stray spaces
    if not re.fullmatch(pattern, value):
        raise UsageError(f"{what} looks wrong")
    return value


def iccid_arg(value: str | None) -> str:
    return _check(r"\d{19,20}", value, "ICCID (expected 19-20 digits)")


DRY_RUN_PLACEHOLDER = "<supplied at send time>"  # preview value when no secret was given


def read_secret(ctx: Ctx, flag: str | None, env_name: str, label: str, required: bool) -> str | None:
    """SIM secret from the environment, a prompt or the flag (which lands in shell history).

    A dry run never prompts: it validates a given secret, else returns a placeholder.
    """
    dry = not ctx.args.yes
    if flag:
        ctx.warn(f"warning: --{label} on the command line is saved in your shell history; "
                 f"prefer {env_name} or the prompt")
        value = flag
    elif ctx.settings.env_value(env_name):
        value = ctx.settings.env_value(env_name)
    elif dry:
        return DRY_RUN_PLACEHOLDER if required else None
    elif getattr(ctx.stdin, "isatty", lambda: False)():
        value = getpass.getpass(f"{label.upper()} (input hidden{'' if required else ', blank to omit'}): ",
                                stream=ctx.err) or None
    else:
        value = None
    if value is None and required:
        raise UsageError(f"{label} is required: set {env_name} or run in a terminal to be prompted")
    if value is not None:
        value = _check(r"[0-9A-Fa-f]{32}", value, f"{label} (expected 32 hex characters)")
        ctx.redactor.add(value)
    return value


# ------------------------------------------------------------------ the safety gate

def mutate(ctx: Ctx, *, path: str, body: dict[str, Any], effect: str, cost: str | None = None,
           note: str | None = None) -> Any:
    """Send a state-changing request once, only with --yes. Without it, print the preview and raise DryRun."""
    url = api.build_url(ctx.settings.base_url(), path)
    # None values are dropped, as when serializing.
    shown_body = sanitize({k: v for k, v in body.items() if v is not None}, ctx.redactor, reveal=True)
    if not ctx.args.yes:
        if ctx.args.json:
            ctx.show_json({"dry_run": True, "method": "POST", "url": url, "body": shown_body,
                           "effect": effect, "cost": cost})
        else:
            ctx.say("Would send (dry run, nothing sent yet):")
            ctx.say(kv([
                ("request", f"POST {url}"),
                ("headers", "Content-Type: application/json, plus AccessKey, Timestamp, RequestID and "
                            "Signature added at send time (values not shown)"),
                ("body", json.dumps(shown_body, separators=(",", ":"), ensure_ascii=False)),
                ("effect", effect),
                ("cost", cost or "no charge documented"),
                *([("note", note)] if note else []),
            ]))
        ctx.warn("dry run: nothing was sent. Add --yes to send this request.")
        raise DryRun
    ctx.mutated = True
    return ctx.client().post(path, body)


# ------------------------------------------------------------------ commands: settings

def _setup_hints(ctx: Ctx) -> list[str]:
    """Credential setup hints for this platform."""
    path = ctx.settings.file_path()
    if path is None:
        try:
            path = str(stores.credentials_path(os.environ))
        except stores.StoreError:
            path = f"no home directory; set {stores.FILE_ENV_VAR}"
    lines = ["", "Lookup order: flag, environment variable, "
                 + (f"{'Keychain' if stores.is_macos() else 'Secret Service'}, " if stores.os_store_name() else "")
                 + f"credentials file ({path})"]
    if stores.is_macos():
        lines.append(f"Store in the Keychain (service {stores.SERVICE}): simlessly config set access-key")
    elif stores.os_store_name() == "secret-service":
        if shutil.which("secret-tool"):
            lines.append("Store in the keyring (Secret Service, via secret-tool): "
                         "simlessly config set access-key --store secret-service")
        else:
            lines.append("secret-tool not found, so the keyring is not used. Desktop: install libsecret-tools "
                         "(apt) / libsecret (dnf, pacman), or use the credentials file.")
        lines.append(f"Headless server: simlessly config set access-key --store file   (writes {path}, mode 0600)")
    else:
        lines.append(f"Store in the credentials file: simlessly config set access-key --store file   ({path})")
    lines.append("CI / systemd: set SIMLESSLY_ACCESS_KEY and SIMLESSLY_SECRET_KEY in the environment.")
    return lines


def cmd_config_check(ctx: Ctx) -> int:
    rows = ctx.settings.describe()
    problem = None
    try:
        ctx.settings.base_url()
    except ConfigError as err:
        problem = str(err)
    file_problem = ctx.settings.file_problem()
    if file_problem and problem == file_problem:
        problem = None  # reported once, below
    ctx.settings.warnings.clear()  # reported below
    os_problem = ctx.settings.os_store_problem()
    ok = all(status.startswith("set") for name, status in rows if name in REQUIRED) and problem is None
    if ctx.args.json:
        ctx.show_json({"ok": ok, "settings": dict(rows), "credentials_file": ctx.settings.file_path(),
                       **({"credentials_file_error": file_problem} if file_problem else {}),
                       **({"os_store_error": os_problem} if os_problem else {}),
                       **({"base_url_error": problem} if problem else {})})
    else:
        ctx.say(table(["setting", "environment variable", "status"],
                      [(name, ENV_VARS[name], status) for name, status in rows]))
        for line in _setup_hints(ctx):
            ctx.say(line)
        if os_problem:
            ctx.say(f"keyring problem: {os_problem}. It was asked once and then skipped for the other settings.")
        if file_problem:
            ctx.say(f"credentials file problem: {file_problem}")
        if problem:
            ctx.say(f"base-url problem: {problem}")
        ctx.say("Ready." if ok else "Not ready: access-key and secret-key are required.")
    return EXIT_OK if ok else EXIT_FAIL


def _setting_arg(value: str) -> str:
    if value not in ENV_VARS:
        raise argparse.ArgumentTypeError(f"unknown setting; choose from {', '.join(ENV_VARS)}")
    return value


def _backends(ctx: Ctx) -> "stores.Backends":
    return ctx.backends or stores.Backends(os.environ)


def _read_setting_value(ctx: Ctx, name: str) -> str:
    """Hidden prompt on a terminal, or one line of stdin with --from-stdin."""
    if ctx.args.from_stdin:
        line = ctx.stdin.readline()
        value = line.rstrip("\r\n")
    elif getattr(ctx.stdin, "isatty", lambda: False)():
        value = getpass.getpass(f"{name} (input hidden): ", stream=ctx.err)
    else:
        raise UsageError("stdin is not a terminal, so there is no way to prompt for the value; "
                         "run this in a terminal, or pipe the value in with --from-stdin")
    try:
        value = stores.clean_value(value, ascii_only=name in SECRET_SETTINGS)
        if name == "base-url":
            value = validate_base_url(value)
    except stores.StoreError as err:
        raise ConfigError(f"{name}: {err}") from None
    if name in SECRET_SETTINGS:
        ctx.redactor.add(value)
    return value


def cmd_config_set(ctx: Ctx) -> int:
    name = ctx.args.setting
    value = _read_setting_value(ctx, name)
    try:
        where = _backends(ctx).store(ctx.args.store, name, value)
    except stores.StoreError as err:
        raise ConfigError(f"could not store {name}: {ctx.redactor.scrub(str(err))}") from None
    ctx.say(f"stored {name} in {where}")
    _warn_if_shadowed(ctx, name, where)
    return EXIT_OK


def _warn_if_shadowed(ctx: Ctx, name: str, where: str) -> None:
    """Warn when a higher-priority source still wins."""
    try:
        winner = ctx.settings.fresh().get(name)
    except ConfigError:
        return
    if winner.source in (None, where):
        return
    if winner.source == "env":
        who, fix = f"the environment variable {ENV_VARS[name]}", f"unset {ENV_VARS[name]}"
    elif winner.source == "flag":
        who, fix = "the command-line flag", "drop the flag"
    elif winner.source == "file":
        who, fix = f"the credentials file {winner.detail}", f"run `simlessly config unset {name} --store file`"
    else:
        who = "the Keychain" if winner.source == "keychain" else "the keyring (Secret Service)"
        fix = f"run `simlessly config unset {name} --store {winner.source}`"
    ctx.warn(f"note: {who} also has {name} and takes precedence over {where}, so the stored value "
             f"is not used. To use it, {fix}.")


def cmd_config_unset(ctx: Ctx) -> int:
    name = ctx.args.setting
    try:
        where, removed = _backends(ctx).delete(ctx.args.store, name)
    except stores.StoreError as err:
        raise ConfigError(f"could not remove {name}: {err}") from None
    ctx.say(f"removed {name} from {where}" if removed else f"{name} was not stored in {where}")
    return EXIT_OK


# ------------------------------------------------------------------ commands: read-only

def _expect_dict(obj: Any, what: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise SimlesslyError(f"unexpected answer shape for {what}", kind="parse")
    return obj


def cmd_configs_list(ctx: Ctx) -> int:
    a = ctx.args
    body = {"configName": a.name, "pageParam": {"total": 0, "pageNum": a.page, "pageSize": a.page_size}}
    obj = _expect_dict(ctx.read_only(api.PATH_CONFIG_LIST, body), "config list")
    configs = obj.get("configs")
    if not isinstance(configs, list):
        raise SimlesslyError("unexpected answer shape for config list", kind="parse")
    if a.json:
        ctx.show_json(sanitize(obj, ctx.redactor))
        return EXIT_OK
    ctx.say(table(["configuration"], [[c] for c in configs]) if configs else "No configurations found.")
    total = (obj.get("pageParam") or {}).get("total")
    ctx.say(f"\n{len(configs)} shown" + (f" of {total}" if isinstance(total, int) else "") + ".")
    ctx.say("Configurations are created in the Simlessly web portal, not through the API.")
    return EXIT_OK


def cmd_profile_show(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    obj = _expect_dict(ctx.read_only(api.PATH_PROFILE_DETAIL, {"iccid": iccid}), "profile detail")
    answered = str(obj.get("iccid", iccid)).strip()
    if answered.upper() != iccid.upper():
        raise SimlesslyError("answer is for a different ICCID; ignoring it", kind="parse")
    reveal = ctx.args.reveal_ac
    view = sanitize(obj, ctx.redactor, reveal)
    if ctx.args.json:
        ctx.show_json(view)
    else:
        raw_status = obj.get("status")
        recycle = view.get("recycleInfo")
        fields = [
            ("ICCID", view.get("iccid")),
            ("Status", raw_status),
            ("Meaning", status_meaning(raw_status)),
            ("EID", view.get("eid")),
            ("IMSI", view.get("imsi")),
            ("SM-DP+ host", view.get("smdp")),
            ("Activation code", view.get("ac")),
            ("Matching ID", view.get("activation")),
            ("QR image link", view.get("acLink")),
            ("Configuration", " / ".join(str(view[k]) for k in ("configurationName", "configurationType") if view.get(k))),
            ("Device brand", view.get("deviceBrand")),
            ("Group", view.get("group")),
            ("Last IP", view.get("ip")),
            ("Created", view.get("createTime")),
            ("Updated", view.get("updateTime")),
            ("Recycle", f"status={recycle.get('status')} expires={recycle.get('expireTime')}"
                        if isinstance(recycle, dict) else None),
        ]
        ctx.say(kv([(k, v) for k, v in fields if v not in (None, "")]))
    if reveal:
        ctx.warn("warning: the activation code above is a bearer secret. Keep it private.")
    return EXIT_OK


# Events that put the profile on a phone (or reissue it). They can follow a DELETED event.
_LATER_EVENTS = {"DOWNLOADED", "INSTALLED", "ENABLED", "DISABLED", "CANCELED"}


def _iso_time(value: Any):
    """Parse an ISO-8601 time, else None. Locale-style times are not parsed: the vendor's day/month order is unknown."""
    try:
        return datetime.fromisoformat(str(value).strip())
    except ValueError:
        return None


def _deleted_verdict(rows: list[dict[str, Any]]) -> str:
    """Off-phone evidence is a DELETED event without a reason (a reason means a failed attempt) that nothing follows."""
    deleted = [r for r in rows if normalize_status(r.get("status")) == "DELETED" and not r.get("reason")]
    if not deleted:
        return ("DELETED event: not found on this page. That is not proof the eSIM is still on a phone, "
                "and no other status proves it left.")
    times = [_iso_time(r.get("createTime")) for r in deleted]
    newest = max((t for t in times if t is not None), default=None) if all(times) else None
    at = clean((deleted[0] if newest is None else deleted[times.index(newest)]).get("createTime"), 40)
    head = f"DELETED event: found" + (f" at {at}" if at else "") + ". The device reported the eSIM was removed."
    others = [r for r in rows if normalize_status(r.get("status")) in _LATER_EVENTS]
    if not others:
        return head
    if newest is not None:
        stamps = [(_iso_time(r.get("createTime")), r) for r in others]
        if all(t is not None for t, _ in stamps):
            later = sorted({normalize_status(r.get("status")) for t, r in stamps if t >= newest})
            if not later:
                return head
            return (head + f" BUT later or simultaneous events ({', '.join(later)}) were recorded: the profile may "
                    "have been reinstalled or reissued and could be on a phone now. Not an off-phone conclusion.")
    return (head + " CAUTION: this page also has other events (DOWNLOADED/INSTALLED/ENABLED/DISABLED/CANCELED) "
            "and the times cannot be ordered here. If any came after the DELETED event, the profile may have "
            "been reinstalled or reissued and could be on a phone now.")


def cmd_profile_log(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    body = {"iccid": iccid, "pageParam": {"pageNum": ctx.args.page, "pageSize": ctx.args.page_size}}
    obj = _expect_dict(ctx.read_only(api.PATH_PROFILE_LOG, body), "profile log")
    rows = obj.get("profileLogs")
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise SimlesslyError("unexpected answer shape for profile log", kind="parse")
    total = (obj.get("pageParam") or {}).get("total")
    incomplete = isinstance(total, int) and total > len(rows)
    if ctx.args.json:
        ctx.show_json(sanitize(obj, ctx.redactor))
        return EXIT_OK
    view = sanitize(rows, ctx.redactor)
    if view:
        ctx.say(table(["time", "event", "reason", "operator", "eid"],
                      [(r.get("createTime"), r.get("status"), clean(r.get("reason"), 60),
                        r.get("operator"), r.get("eid")) for r in view]))
    else:
        ctx.say("No log entries.")
    ctx.say(f"\n{len(rows)} entries shown" + (f" of {total}" if isinstance(total, int) else "")
            + " (times are as Simlessly formats them, not sorted here).")
    if incomplete:
        ctx.say("The log is incomplete: use --page to read further pages before drawing conclusions.")
    ctx.say(_deleted_verdict(rows))
    return EXIT_OK


def _pick(d: dict[str, Any], *names: str) -> Any:
    """First present key; the vendor spells some keys differently in its table and examples."""
    return next((d[n] for n in names if n in d), None)


def cmd_batch_result(ctx: Ctx) -> int:
    batch = _check(r"[A-Za-z0-9_-]{1,64}", ctx.args.batch_id, "batch id")
    obj = _expect_dict(ctx.read_only(api.PATH_BATCH_INFO, {"batchCode": batch}), "batch result")
    info = obj.get("batchTaskInfo") or {}  # absent while the task is processing
    if not isinstance(info, dict):
        raise SimlesslyError("unexpected answer shape for batch task info (batchTaskInfo is not an object)",
                             kind="parse")
    results = _pick(obj, "results", "result") or []
    if not isinstance(results, list):
        raise SimlesslyError("unexpected answer shape for batch results", kind="parse")
    if ctx.args.json:
        ctx.show_json(sanitize(obj, ctx.redactor))
        return EXIT_OK
    fields = [
        ("Batch", info.get("batchCode")), ("Task", info.get("taskType")), ("Status", info.get("status")),
        ("Total", info.get("total")), ("Succeeded", _pick(info, "succeedNum", "succeed")),
        ("Failed", _pick(info, "failedNum", "failed")), ("Created", info.get("createTime")),
    ]
    shown = [(k, v) for k, v in fields if v not in (None, "")]
    ctx.say(kv(shown) if shown else "Simlessly returned no batch task info (the task may still be starting).")
    view = sanitize([r for r in results if isinstance(r, dict)], ctx.redactor)
    if view:
        ctx.say("")
        ctx.say(table(["iccid", "success", "error", "eid", "activation code"],
                      [(r.get("iccid"), str(r.get("success")).lower(),
                        clean(_pick(r, "errorReason", "errorReson"), 60), r.get("eid"),
                        r.get("activationCode")) for r in view]))
    return EXIT_OK


# ------------------------------------------------------------------ commands: state-changing

def cmd_ac_generate(ctx: Ctx) -> int:
    a = ctx.args
    config = a.config or ctx.settings.get("config-name").value
    if not config:
        raise UsageError("--config is required (or set SIMLESSLY_CONFIG_NAME); list them with `simlessly configs list`")
    iccid = iccid_arg(a.iccid)
    imsi = _check(r"\d{15}", a.imsi, "IMSI (expected 15 digits)")
    ki = read_secret(ctx, a.ki, ENV_SIM_KI, "ki", required=True)
    opc = read_secret(ctx, a.opc, ENV_SIM_OPC, "opc", required=False)
    msisdn = _check(r"\+?\d{1,15}", a.msisdn, "MSISDN (expected up to 15 digits)") if a.msisdn else None
    body = {"iccid": iccid, "imsi": imsi, "ki": ki, "opc": opc, "msisdn": msisdn,
            "needAcLink": a.ac_link, "configName": config}
    obj = mutate(
        ctx, path=api.PATH_GENERATE_AC, body=body,
        effect="creates a profile for this SIM and returns a live activation code that a phone can install",
        cost="may cost money: installing the code consumes a Simlessly download credit; "
             "it also sends the SIM's secret keys to Simlessly",
        note="fails if the ICCID already exists on the platform")
    obj = _expect_dict(obj, "generate")
    code = obj.get("activationCode")
    if not isinstance(code, str) or not code.strip():
        raise SimlesslyError("Simlessly accepted the request but returned no readable activation code; "
                             "check the profile before retrying", kind="parse")
    if str(obj.get("iccid", iccid)).strip() != iccid:
        raise SimlesslyError("answer is for a different ICCID", kind="parse")
    ctx.redactor.add(code)
    reveal = a.reveal_ac
    if ctx.args.json:
        ctx.show_json(sanitize(obj, ctx.redactor, reveal))
    else:
        link = obj.get("acLink")
        shown = (lambda v: v) if reveal else mask_tail
        ctx.say("Generated.")
        ctx.say(kv([
            ("ICCID", iccid),
            ("Activation code", shown(code)),
            ("QR payload (LPA)", shown("LPA:" + code)),
            *([("QR image link", shown(link))] if link else []),
        ]))
    if reveal:
        ctx.warn("warning: the activation code is a bearer secret. Anyone with it can install this eSIM.")
    else:
        ctx.warn(f"note: the activation code is masked. Show it with `simlessly profile show {iccid} --reveal-ac`.")
    return EXIT_OK


def _simple_mutation(ctx: Ctx, path: str, body: dict[str, Any], *, effect: str, cost: str | None,
                     done: str, note: str | None = None) -> int:
    obj = mutate(ctx, path=path, body=body, effect=effect, cost=cost, note=note)
    if ctx.args.json:
        ctx.show_json(sanitize(obj, ctx.redactor) if obj is not None else {"success": True})
    else:
        ctx.say(done)
    return EXIT_OK


def cmd_profile_expire(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    return _simple_mutation(
        ctx, api.PATH_PROFILE_EXPIRED, {"iccid": iccid},
        effect="invalidates the profile's current activation code (status becomes EXPIRED)",
        cost="no charge documented", note="use only for a download/install fault; it does not remove the "
        "profile from a phone. Needs status Downloaded/Installed/Enabled/Disabled",
        done=f"Expired {iccid}. Status is now EXPIRED: {status_meaning('EXPIRED')}.")


def cmd_profile_delete(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    return _simple_mutation(
        ctx, api.PATH_PROFILE_DELETE, {"iccid": iccid, "force": False},
        effect="removes the profile and its activation code from the Simlessly platform (status REMOVED)",
        cost="no charge documented", note="platform-side only; do not delete while the line is still "
        "enabled or disabled on a device. The documented 'force' option is never set to true",
        done=f"Deleted {iccid} from the platform. Status REMOVED: {status_meaning('REMOVED')}.")


def cmd_order_cancel(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    return _simple_mutation(
        ctx, api.PATH_ES2_CANCEL, {"iccid": iccid},
        effect="ES2+ step 1 of 3: cancels the current order, so the old activation code stops working "
               "(status becomes CANCELED)",
        cost="no charge documented", note="needs status Available or Error. After this the profile has no usable "
        "code until you run `order download` then `order confirm`",
        done=f"Cancelled the order for {iccid}. Status CANCELED: {status_meaning('CANCELED')}. "
             "Next: simlessly order download, then order confirm.")


def cmd_order_download(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    config = ctx.args.config or ctx.settings.get("config-name").value
    if not config:
        raise UsageError("--config is required (or set SIMLESSLY_CONFIG_NAME)")
    return _simple_mutation(
        ctx, api.PATH_ES2_DOWNLOAD, {"iccid": iccid, "configName": config},
        effect="ES2+ step 2 of 3: creates a download order for the profile (status is unchanged)",
        cost="may cost money as part of issuing a new code", note="then run `order confirm`",
        done=f"Download order created for {iccid}. Next: simlessly order confirm {iccid} --yes.")


def cmd_order_confirm(ctx: Ctx) -> int:
    iccid = iccid_arg(ctx.args.iccid)
    obj = mutate(
        ctx, path=api.PATH_ES2_CONFIRM, body={"iccid": iccid, "confirmationCode": "", "ac": ""},
        effect="ES2+ step 3 of 3: confirms the order and issues a new activation code (status becomes AVAILABLE)",
        cost="may cost money: installing the new code is a new download credit",
        note="the new code is masked unless --reveal-ac is given")
    reveal = ctx.args.reveal_ac
    view = sanitize(obj, ctx.redactor, reveal) if isinstance(obj, dict) else None
    if ctx.args.json:
        ctx.show_json(view if view is not None else {"success": True})
    elif view and view.get("ac"):
        ctx.say(f"Confirmed {iccid}. New code issued.")
        ctx.say(kv([("Activation code", view["ac"]), *([("EID", view["eid"])] if view.get("eid") else [])]))
    else:
        ctx.say(f"Confirmed {iccid}, but Simlessly returned no activation code. "
                f"Check with: simlessly profile show {iccid}")
    if reveal and view and view.get("ac"):
        ctx.warn("warning: the activation code is a bearer secret. Keep it private.")
    return EXIT_OK


# ------------------------------------------------------------------ parser

class _Parser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # No abbreviations: `--y` must not send.
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message: str):  # type: ignore[override]
        prefix = "unrecognized arguments: "
        if message.startswith(prefix):
            # Do not echo values after an unknown option: they may be secrets.
            names = [t.split("=", 1)[0] for t in message[len(prefix):].split() if t.startswith("-")]
            message = ("unrecognized option(s): " + " ".join(dict.fromkeys(names)) if names
                       else "unrecognized argument(s)") + " (values are not shown)"
        raise UsageError(message, self.format_usage())


def _bounded_number(name: str, low: float, high: float, integer: bool) -> Callable[[str], Any]:
    def convert(text: str) -> Any:
        try:
            value = int(text) if integer else float(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{name} must be {'a whole number' if integer else 'a number'}") from None
        if (not integer and not math.isfinite(value)) or not low <= value <= high:
            raise argparse.ArgumentTypeError(f"{name} must be between {low:g} and {high:g}")
        return value
    convert.__name__ = name
    return convert


timeout_arg = _bounded_number("timeout", 0.1, 120, integer=False)
page_arg = _bounded_number("page", 1, 10000, integer=True)
page_size_arg = _bounded_number("page-size", 1, 1000, integer=True)


def _add_common(p: argparse.ArgumentParser, root: bool) -> None:
    """Options accepted before or after the subcommand. On subparsers they default to SUPPRESS, so they keep an earlier value."""
    d = (lambda v: v) if root else (lambda v: argparse.SUPPRESS)
    p.add_argument("--json", action="store_true", default=d(False), help="print masked JSON instead of tables")
    p.add_argument("--timeout", type=timeout_arg, default=d(api.DEFAULT_TIMEOUT), metavar="SECONDS",
                   help=f"HTTP timeout in seconds, 0.1-120 (default {api.DEFAULT_TIMEOUT:g})")
    p.add_argument("--base-url", default=d(None), metavar="URL",
                   help="override SIMLESSLY_BASE_URL (vendor origin or http://127.0.0.1 only)")
    p.add_argument("--debug", action="store_true", default=d(False),
                   help="log requests and answers to stderr, secrets redacted")


def build_parser() -> argparse.ArgumentParser:
    root = _Parser(prog="simlessly", description="Command-line client for the Simlessly RSP API. "
                   "State-changing commands are a dry run unless --yes is given.")
    root.add_argument("--version", action="version", version=f"simlessly-cli {__version__}")
    _add_common(root, root=True)
    groups = root.add_subparsers(dest="group", required=True, metavar="<group>", parser_class=_Parser)

    def group(name: str, help_: str):
        g = groups.add_parser(name, help=help_)
        return g.add_subparsers(dest="command", required=True, metavar="<command>", parser_class=_Parser)

    def leaf(sub, name: str, help_: str, func: Callable[[Ctx], int], *, mutating: bool = False):
        p = sub.add_parser(name, help=help_, description=help_)
        _add_common(p, root=False)
        if mutating:
            p.add_argument("--yes", action="store_true", help="send the request (default: dry run, exit 2)")
        else:
            p.set_defaults(yes=False)
        p.set_defaults(func=func)
        return p

    s = group("config", "check where settings come from, store or remove them")
    leaf(s, "check", "show which settings are set and from where (never the values)", cmd_config_check)
    store_help = ("where to store it: auto (Keychain on macOS, Secret Service on Linux if secret-tool works, "
                  "else the file), keychain, secret-service or file")
    p = leaf(s, "set", "store a setting (hidden prompt, never from the command line)", cmd_config_set)
    p.add_argument("setting", type=_setting_arg, metavar="<setting>", help="one of: " + ", ".join(ENV_VARS))
    p.add_argument("--store", choices=stores.STORES, default="auto", help=store_help)
    p.add_argument("--from-stdin", action="store_true",
                   help="read the value as one line from stdin (required when stdin is not a terminal)")
    p = leaf(s, "unset", "remove a stored setting", cmd_config_unset)
    p.add_argument("setting", type=_setting_arg, metavar="<setting>", help="one of: " + ", ".join(ENV_VARS))
    p.add_argument("--store", choices=stores.STORES, default="auto", help=store_help)

    s = group("configs", "profile configurations")
    p = leaf(s, "list", "list profile configuration names (also checks the credentials)", cmd_configs_list)
    p.add_argument("--name", help="filter by name")
    p.add_argument("--page", type=page_arg, default=1, help="page number, 1-10000")
    p.add_argument("--page-size", type=page_size_arg, default=100, help="entries per page, 1-1000")

    s = group("profile", "inspect and manage one profile")
    p = leaf(s, "show", "show a profile's status and what it means", cmd_profile_show)
    p.add_argument("iccid")
    p.add_argument("--reveal-ac", action="store_true", help="print the activation code in full")
    p = leaf(s, "log", "show a profile's event history", cmd_profile_log)
    p.add_argument("iccid")
    p.add_argument("--page", type=page_arg, default=1, help="page number, 1-10000")
    p.add_argument("--page-size", type=page_size_arg, default=100, help="entries per page, 1-1000")
    leaf(s, "expire", "invalidate the current activation code (ES2+ expire)", cmd_profile_expire, mutating=True).add_argument("iccid")
    leaf(s, "delete", "delete the profile from the platform", cmd_profile_delete, mutating=True).add_argument("iccid")

    s = group("batch", "batch generation results")
    leaf(s, "result", "poll a batch generation task", cmd_batch_result).add_argument("batch_id")

    s = group("ac", "activation codes")
    p = leaf(s, "generate", "generate a profile and activation code for one SIM", cmd_ac_generate, mutating=True)
    p.add_argument("--config", help="profile configuration name (default: SIMLESSLY_CONFIG_NAME)")
    p.add_argument("--iccid", required=True)
    p.add_argument("--imsi", required=True)
    p.add_argument("--ki", help=f"SIM key (prefer env {ENV_SIM_KI} or the prompt)")
    p.add_argument("--opc", help=f"SIM OPc (prefer env {ENV_SIM_OPC} or the prompt)")
    p.add_argument("--msisdn")
    p.add_argument("--ac-link", action=argparse.BooleanOptionalAction, default=True,
                   help="also ask for a QR image link (default on)")
    p.add_argument("--reveal-ac", action="store_true",
                   help="print the activation code, LPA payload and QR link in full")

    s = group("order", "ES2+ reissue steps: cancel, download, confirm")
    leaf(s, "cancel", "step 1: cancel the current order", cmd_order_cancel, mutating=True).add_argument("iccid")
    p = leaf(s, "download", "step 2: create a download order", cmd_order_download, mutating=True)
    p.add_argument("iccid")
    p.add_argument("--config", help="profile configuration name (default: SIMLESSLY_CONFIG_NAME)")
    p = leaf(s, "confirm", "step 3: confirm and receive a new activation code", cmd_order_confirm, mutating=True)
    p.add_argument("iccid")
    p.add_argument("--reveal-ac", action="store_true", help="print the new activation code in full")

    from . import portal_cli  # imported here: it uses helpers defined above
    portal_cli.register(group, leaf)
    return root


# ------------------------------------------------------------------ entry points

def main(argv: list[str] | None = None, *, env=None, keychain: KeychainLookup | None = keychain_lookup,
         stdout: TextIO | None = None, stderr: TextIO | None = None, stdin: TextIO | None = None,
         backends: "stores.Backends | None" = None, credentials_file: "stores.CredentialsFile | None" = None) -> int:
    """Run the CLI and return the exit code. Streams, env and secret stores are injectable for tests."""
    env = os.environ if env is None else env
    out, err, inp = stdout or sys.stdout, stderr or sys.stderr, stdin or sys.stdin
    try:
        args = build_parser().parse_args(argv)
    except UsageError as e:
        err.write(e.usage + f"simlessly: error: {e}\n")
        return EXIT_USAGE
    except SystemExit as e:  # --help / --version
        return int(e.code or 0)

    if credentials_file is None:
        credentials_file = stores.CredentialsFile.for_env(env)  # path resolved lazily
    source = (stores.os_store_name() or "keychain") if keychain is keychain_lookup else "keychain"
    settings = Settings(env, keychain, overrides={"base-url": args.base_url},
                        file_store=credentials_file, keychain_source=source)
    ctx = Ctx(args, settings, Redactor(), out, err, inp, backends or stores.Backends(env))
    try:
        return args.func(ctx)
    except DryRun:
        return EXIT_USAGE
    except UsageError as e:
        err.write(f"error: {e}\n")
        return EXIT_USAGE
    except ConfigError as e:
        err.write(f"error: {e}\n")
        return EXIT_FAIL
    except SimlesslyError as e:
        err.write(f"error: {ctx.redactor.scrub(str(e))}\n")
        if ctx.mutated and e.outcome_unknown:
            err.write(f"OUTCOME UNKNOWN: Simlessly may have acted. Nothing was retried. {ctx.check_hint} "
                      "before sending again.\n")
            return EXIT_UNKNOWN
        return EXIT_FAIL
    except Exception as e:  # last resort; a raw traceback could quote a credential
        err.write(f"error: unexpected {type(e).__name__}: {ctx.redactor.scrub(clean(str(e), 200))}\n")
        if ctx.mutated:
            err.write(f"OUTCOME UNKNOWN: Simlessly may have acted. Nothing was retried. {ctx.check_hint} "
                      "before sending again.\n")
            return EXIT_UNKNOWN
        return EXIT_FAIL
    finally:
        for warning in settings.warnings:  # e.g. a refused credentials file
            err.write(f"warning: {warning} (ignored for optional settings, which use their defaults)\n")


def main_entry() -> None:
    # On a legacy code page, print a replacement character instead of raising on vendor text.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    sys.exit(main())
