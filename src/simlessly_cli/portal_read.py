"""`simlessly portal ...`: the read-only commands (lists, lookups, statistics, profile view, summary, QR image).

Every call goes through `portal_cli._read` (PortalClient.read / read_bytes), which refuses any path not in
portal.READ_METHODS, so no state-changing path is reachable here. Output is masked as in `portal fleet`, and
paged lists use the same page walker and completeness rules as `portal fleet --all`.
"""

from __future__ import annotations

import calendar
import os
import re
from datetime import date, datetime, timedelta
from typing import Any, Callable

from . import portal
from .cli import EXIT_FAIL, EXIT_OK, Ctx, UsageError, _check, _pick, iccid_arg
from .client import SimlesslyError
from .config import ConfigError
from .output import clean, kv, normalize_status, sanitize, status_meaning, table
from . import portal_cli
from .portal_cli import (
    STATUS_CAVEAT, _completeness, _fetch_fleet, _fetch_pages, _fleet_filters, _page_rows, _paging_facts,
    _paging_warnings, _parse_when, _read, _resolve_config, _rows_view, _total, _when, add_paging,
)

ON_PHONE_STATUSES = ("DOWNLOADED", "INSTALLED", "ENABLED", "DISABLED")
PROFILE_STATUSES = ("AVAILABLE", "DOWNLOADED", "INSTALLED", "ENABLED", "DISABLED", "DELETED", "CANCELED", "EXPIRED", "ERROR")
DEFAULT_REPORT_STATUSES = ("AVAILABLE", "ENABLED", "DISABLED", "DELETED", "ERROR")
BATCH_TYPES = ("GENERATE_AC", "BATCH_GENERATE", "RE_GENERATE", "SINGLE_GENERATE", "OPEN_BATCH_GENERATE")
ENUM_NAMES = ("profileStatus", "profileOperationStatus", "configTypes")


# ------------------------------------------------------------------ shared pieces

def _need_dict(obj: Any, what: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise SimlesslyError(f"unexpected answer shape for {what}", kind="parse")
    return obj


def _need_list(obj: Any, what: str) -> list[dict[str, Any]]:
    if not isinstance(obj, list) or not all(isinstance(r, dict) for r in obj):
        raise SimlesslyError(f"unexpected answer shape for {what} (expected a list)", kind="parse")
    return obj


def _list_in(obj: Any, key: str, what: str) -> list[dict[str, Any]]:
    """obj[key] as a list of objects."""
    return _need_list(_need_dict(obj, what).get(key), what)


def _date_filter(ctx: Ctx, since: str | None, until: str | None) -> tuple[str, str | None]:
    """(startTime, endTime) as epoch-ms strings; '' for no start, None (omitted) for no end."""
    start = _parse_when(since, "--since", end=False) if since else ""
    end = _parse_when(until, "--until", end=True) if until else None
    if start and end and int(start) > int(end):
        raise UsageError("--since is after --until")
    return start, end


def _count_of(*parts: Any) -> str:
    return ", ".join(f"{k}={v}" for k, v in parts if v not in (None, ""))


def _run_list(ctx: Ctx, *, path: str, what: str, body: Callable[[int], dict[str, Any]], columns: list[tuple[str, Callable[[dict], Any]]],
              noun: str, narrow: str, reveal: bool = False, note: str | None = None) -> int:
    """A paged portal list: fetch (one page or --all), mask, print a table or JSON."""
    a = ctx.args
    if a.all and a.page is not None:
        raise UsageError("--all fetches every page; do not combine it with --page")
    body(1)                                                  # validate the filters before any call
    obj, rows, total, pages, stop = _fetch_pages(ctx, path, body, what, page_size=a.page_size, page=a.page,
                                                 walk_all=a.all)
    _paging_warnings(ctx, a.all, rows, total, stop, narrow)
    view = _rows_view(rows, ctx, reveal)
    if a.json:
        result = sanitize(obj, ctx.redactor, imsi_text=True)
        result["pageData"] = view
        if a.all:
            result.update(_paging_facts(pages, stop, rows, total))
        ctx.show_json(result)
    else:
        if view:
            ctx.say(table([h for h, _ in columns], [[fn(r) for _, fn in columns] for r in view]))
        else:
            ctx.say(f"No {noun} found.")
        shown = f"\n{len(rows)} {noun} shown" + (f" of {total}" if total is not None else "")
        if a.all:
            shown += f" ({pages} page{'s' if pages != 1 else ''} fetched)"
        elif total is not None and len(rows) < total:
            shown += "; use --page, or --all to fetch every page"
        ctx.say(shown + ".")
        if note:
            ctx.say(note)
    if reveal:
        ctx.warn("warning: activation codes and the links to files that hold them are bearer secrets.")
    if getattr(a, "strict", False) and a.all and _completeness(stop, rows, total)[0] is False:
        ctx.warn("error: --strict: the list is known to be incomplete (see the warning above).")
        return EXIT_FAIL
    return EXIT_OK


def _run_array(ctx: Ctx, *, obj: Any, what: str, columns: list[tuple[str, Callable[[dict], Any]]], noun: str,
               note: str | None = None, reveal: bool = False) -> int:
    """A portal answer that is a bare array, not a page (groups, EID pushes, recycle states)."""
    rows = _need_list(obj, what)
    view = _rows_view(rows, ctx, reveal)
    if ctx.args.json:
        ctx.show_json(view)
    else:
        if view:
            ctx.say(table([h for h, _ in columns], [[fn(r) for _, fn in columns] for r in view]))
        else:
            ctx.say(f"No {noun} found.")
        ctx.say(f"\n{len(rows)} {noun}.")
        if note:
            ctx.say(note)
    if reveal:
        ctx.warn("warning: activation codes are bearer secrets. Anyone with one can install that eSIM.")
    return EXIT_OK


def _col(*names: str) -> Callable[[dict], Any]:
    return lambda row: _pick(row, *names)


def _time_col(*names: str) -> Callable[[dict], Any]:
    return lambda row: _when(_pick(row, *names))


def _kv_view(ctx: Ctx, obj: Any, what: str, reveal: bool = False) -> dict[str, Any]:
    return _rows_view([_need_dict(obj, what)], ctx, reveal)[0]


def _flat_pairs(view: dict[str, Any]) -> list[tuple[str, Any]]:
    """Top-level fields for a key/value display; nested values as compact JSON."""
    import json as _json
    out = []
    for key, value in view.items():
        if value in (None, ""):
            continue
        if isinstance(value, (dict, list)):
            value = _json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        out.append((key, clean(value, 160)))
    return out


# ------------------------------------------------------------------ profile (the portal's view of one ICCID)

def find_profile(ctx: Ctx, iccid: str) -> dict[str, Any]:
    """The fleet row whose ICCID is exactly `iccid`. Raises when there is none."""
    body = {"iccid": iccid, "iccidList": "", "status": "", "configId": "", "startTime": "", "endTime": "",
            "groupId": "", "recycleStatus": "", "acString": "", "msisdn": "",
            "pageParam": {"pageNum": 1, "pageSize": 20}}
    rows = _page_rows(_read(ctx, portal.PATH_FLEET_LIST, body), "fleet list")
    exact = [r for r in rows if str(r.get("iccid", "")).strip().upper() == iccid.upper()]
    if not exact:
        raise SimlesslyError(f"the portal's fleet has no profile with ICCID {iccid}", kind="api")
    if len(exact) > 1:
        raise SimlesslyError(f"the portal's fleet lists ICCID {iccid} more than once; nothing was done", kind="parse")
    return exact[0]


def recycle_states(ctx: Ctx, iccids: list[str]) -> list[dict[str, Any]]:
    return _need_list(_read(ctx, portal.PATH_FLEET_RECYCLE_QUERY, {"iccid": iccids}), "recycle query")


def cmd_portal_profile(ctx: Ctx) -> int:
    a = ctx.args
    iccid = iccid_arg(a.iccid)
    row = find_profile(ctx, iccid)
    recycle = recycle_states(ctx, [iccid])
    tx = _read(ctx, portal.PATH_FLEET_TRANSACTION, {"iccid": iccid})
    tx_rows = _page_rows(tx, "profile transactions") if isinstance(tx, dict) and tx.get("pageData") is not None else []
    tx_total = _total(tx)
    reveal = a.reveal_ac
    view = _rows_view([row], ctx, reveal)[0]
    rec_view = _rows_view(recycle, ctx, False)
    tx_view = sanitize(tx_rows, ctx.redactor, imsi_text=True)
    if a.json:
        ctx.show_json({"profile": view, "recycle": rec_view,
                       "transactions": {"pageData": tx_view, "total": tx_total}})
    else:
        raw_status = row.get("status")
        config = _pick(view, "configName", "configurationName", "config")
        fields = [
            ("ICCID", view.get("iccid")), ("Portal id", view.get("id")),
            ("Status", raw_status), ("Meaning", status_meaning(raw_status) if raw_status else None),
            ("Configuration", " / ".join(str(x) for x in (config, view.get("configType")) if x not in (None, ""))),
            ("Config id", view.get("configId")), ("MSISDN", view.get("msisdn")),
            ("EID", view.get("eid")), ("IMSI", view.get("imsi")), ("SM-DP+", view.get("smdp")),
            ("Activation code", _pick(view, "ac", "acString")), ("Matching ID", view.get("activation")),
            ("QR image link", view.get("acLink")),
            ("Group", view.get("groupName")), ("Notes", view.get("notes")),
            ("Brand", view.get("brand")), ("Last IP", view.get("clientIp")),
            ("Region / SPN", " / ".join(str(x) for x in (view.get("region"), view.get("spn")) if x not in (None, ""))),
            ("Recycle status", view.get("recycleStatus")), ("Recycle estimate", _when(view.get("estimateTime"))),
            ("Blocked", view.get("isBlock")), ("Campaign profile", view.get("campaignFlag")),
            ("Order", view.get("orderId")), ("Created by", view.get("createBy")),
            ("Created", _when(view.get("createTime"))), ("Updated", _when(view.get("updateTime"))),
        ]
        ctx.say(kv([(k, v) for k, v in fields if v not in (None, "")]))
        for rec in rec_view:
            ctx.say("\nRecycle state: " + _count_of(
                ("status", rec.get("status")), ("estimated", _when(rec.get("estimatedTime"))),
                ("recycled", _when(rec.get("recycledTime"))), ("reason", clean(rec.get("recycledReason"), 80)),
                ("applet received", rec.get("received")), ("recycle received", rec.get("recycleReceived"))))
        if tx_view:
            ctx.say("\nStatus timeline (first page):")
            ctx.say(table(["time", "status", "reason", "operator"],
                          [(_when(r.get("createTime")), r.get("status"), clean(r.get("reason"), 60), r.get("operator"))
                           for r in tx_view]))
            if tx_total is not None and tx_total > len(tx_view):
                ctx.say(f"{len(tx_view)} of {tx_total} transactions shown; `simlessly portal logs --iccid {iccid} --all` has the full log.")
        ctx.say("\n" + STATUS_CAVEAT)
    if reveal:
        ctx.warn("warning: the activation code above is a bearer secret. Keep it private.")
    return EXIT_OK


# ------------------------------------------------------------------ logs: detail, batch (generate-AC), recycle

def cmd_portal_log_detail(ctx: Ctx) -> int:
    log_id = _check(r"[A-Za-z0-9_-]{1,40}", ctx.args.log_id, "log id (the `log id` column of `portal logs`)")
    obj = _read(ctx, portal.PATH_LOG_PROFILE_DETAIL, {"id": log_id})
    view = _kv_view(ctx, obj, "profile log detail")
    if ctx.args.json:
        ctx.show_json(view)
    else:
        fields = [("EID", view.get("eid")), ("IP", view.get("ip")), ("Brand", view.get("brand")),
                  ("Device type", view.get("deviceType")), ("Device name", view.get("deviceName"))]
        shown = [(k, v) for k, v in fields if v not in (None, "")]
        ctx.say(kv(shown) if shown else "The portal returned no device details for that log entry.")
    return EXIT_OK


def _progress(row: dict[str, Any]) -> str:
    total, done, ok_ = row.get("total"), row.get("processed"), row.get("succeed")
    if isinstance(total, int) and total > 0:
        part = done if str(row.get("process", "")).upper() == "PROCESSING" else ok_
        if isinstance(part, int):
            return f"{part}/{total}"
    return ""


def _failed(row: dict[str, Any]) -> Any:
    total, ok_ = row.get("total"), row.get("succeed")
    if str(row.get("process", "")).upper() != "PROCESSING" and isinstance(total, int) and isinstance(ok_, int):
        return total - ok_
    return ""


def cmd_portal_batch_logs(ctx: Ctx) -> int:
    a = ctx.args

    def body(page: int) -> dict[str, Any]:
        start, end = _date_filter(ctx, a.since, a.until)
        return {"type": a.type or "", "process": a.process or "", "acFormat": a.format or "",
                "startTime": start, "endTime": end, "pageParam": {"pageNum": page, "pageSize": a.page_size}}
    cols = [("created", _time_col("createTime")), ("type", _col("type")),
            ("formats", lambda r: clean(r.get("acFormat"))), ("process", _col("process")),
            ("progress", _progress), ("failed", _failed), ("configuration", _col("configuration")),
            ("by", _col("createBy")), ("ended", _time_col("endTime")),
            ("AC file", lambda r: "yes" if r.get("acUrl") else ""),
            ("error report", lambda r: "yes" if r.get("resultUrl") else "")]
    return _run_list(ctx, path=portal.PATH_LOG_BATCH_TASK_LIST, what="generate-AC log list", body=body, columns=cols,
                     noun="batch tasks", narrow="--type, --process, --format, --since, --until", reveal=a.reveal_ac,
                     note="The link to the generated AC file and the error-report link are in --json (masked). --reveal-ac shows the "
                          "AC file link only; the error-report link always stays masked.")


def cmd_portal_recycle_logs(ctx: Ctx) -> int:
    a = ctx.args

    def body(page: int) -> dict[str, Any]:
        start, end = _date_filter(ctx, a.since, a.until)
        return {"iccid": _check(r"\d{1,20}", a.iccid, "--iccid (digits)") if a.iccid else "",
                "orderId": _check(r"[A-Za-z0-9_-]{1,64}", a.order_id, "--order-id") if a.order_id else "",
                "startTime": start, "endTime": end, "pageParam": {"pageNum": page, "pageSize": a.page_size}}
    cols = [("time", _time_col("recycleTime")), ("iccid", _col("iccid")), ("order", _col("orderId")),
            ("status", _col("recycleStatus")), ("reason", lambda r: clean(r.get("recycleReason"), 60))]
    return _run_list(ctx, path=portal.PATH_LOG_RECYCLE_LIST, what="recycle log list", body=body, columns=cols,
                     noun="recycle log entries", narrow="--iccid, --order-id, --since, --until")


def cmd_portal_recycle_status(ctx: Ctx) -> int:
    iccids = [iccid_arg(x) for x in ctx.args.iccids]
    obj = recycle_states(ctx, iccids)
    cols = [("iccid", _col("iccid")), ("status", _col("status")), ("estimated", _time_col("estimatedTime")),
            ("recycled", _time_col("recycledTime")), ("reason", lambda r: clean(r.get("recycledReason"), 60)),
            ("applet received", _col("received")), ("recycle received", _col("recycleReceived"))]
    return _run_array(ctx, obj=obj, what="recycle query", columns=cols, noun="recycle states",
                      note="AWAITING means the recycle applet will remove the profile from the phone when it next connects.")


# ------------------------------------------------------------------ campaigns, groups, configs, blocks, pushes

def cmd_portal_campaigns(ctx: Ctx) -> int:
    a = ctx.args
    cols = [("id", _col("campaignId")), ("name", _col("campaignName")), ("configuration", _col("configurationName")),
            ("status", _col("status")), ("available", _col("availableProfiles")), ("total", _col("totalProfiles")),
            ("activation code", _col("ac"))]
    # campaign/list is a GET with flat pageNum / pageSize parameters (no pageParam)
    return _run_list(ctx, path=portal.PATH_CAMPAIGN_LIST, what="campaign list",
                     body=lambda page: {"pageNum": page, "pageSize": a.page_size}, columns=cols, noun="campaigns",
                     narrow="none available", reveal=a.reveal_ac)


def cmd_portal_campaign_profiles(ctx: Ctx) -> int:
    a = ctx.args
    cid = _check(r"[A-Za-z0-9_-]{1,40}", a.campaign_id, "campaign id")
    campaign_id: Any = int(cid) if cid.isdigit() else cid
    cols = [("resource id", _col("campaignResourceId")), ("iccid", _col("iccid")), ("status", _col("status")),
            ("eid", _col("eid")), ("created", _time_col("createTime"))]

    def body(page: int) -> dict[str, Any]:
        return {"campaignId": campaign_id,
                "iccid": _check(r"\d{1,20}", a.iccid, "--iccid (digits)") if a.iccid else "",
                "eid": _check(r"\d{1,32}", a.eid, "--eid (digits)") if a.eid else "",
                "pageParam": {"pageNum": page, "pageSize": a.page_size}}
    return _run_list(ctx, path=portal.PATH_CAMPAIGN_RESOURCE_LIST, what="campaign profile list", body=body, columns=cols,
                     noun="campaign profiles", narrow="--iccid, --eid",
                     note="LOCKED = in use by a device, IDLE = not yet used (campaign profiles).")


def cmd_portal_groups(ctx: Ctx) -> int:
    obj = _read(ctx, portal.PATH_GROUP_LIST, {})
    cols = [("id", _col("id")), ("name", _col("name")), ("profiles", _col("count")), ("note", lambda r: clean(r.get("note"), 60))]
    return _run_array(ctx, obj=obj, what="group list", columns=cols, noun="groups")


def _hplmn(row: dict[str, Any]) -> Any:
    value = row.get("hplmn")
    return value.get("plmn") if isinstance(value, dict) else value


def cmd_portal_configs(ctx: Ctx) -> int:
    a = ctx.args
    cols = [("config id", _col("configId")), ("name", _col("configName")), ("type", _col("configType")),
            ("subtype", _col("configSubType")), ("HPLMN", _hplmn), ("max download", _col("maxDownload")),
            ("max attempt", _col("maxAttempt"))]

    def body(page: int) -> dict[str, Any]:
        name = _check(r"[^\x00-\x1f\x7f]{1,128}", a.name, "--name") if a.name else ""
        return {"pageParam": {"pageNum": page, "pageSize": a.page_size}, "configName": name}
    return _run_list(ctx, path=portal.PATH_CONFIG_QUERY, what="configuration list", body=body, columns=cols,
                     noun="configurations", narrow="--name",
                     note="Configurations are created in the Simlessly portal; `portal fleet --config` takes a name or a config id.")


def cmd_portal_config(ctx: Ctx) -> int:
    config_id = _check(r"[A-Za-z0-9_-]{1,64}", ctx.args.config_id, "config id")
    obj = _read(ctx, portal.PATH_CONFIG_DETAIL, {"configId": config_id})
    view = _kv_view(ctx, obj, "configuration detail")
    if ctx.args.json:
        ctx.show_json(view)
    else:
        ctx.say(kv(_flat_pairs(view)))
    return EXIT_OK


def cmd_portal_blocks(ctx: Ctx) -> int:
    a = ctx.args
    cols = [("eid", _col("eid")), ("iccid", _col("iccid")), ("reason", lambda r: clean(r.get("reason"), 60)),
            ("created", _time_col("createTime")), ("by", _col("createBy"))]

    def body(page: int) -> dict[str, Any]:
        return {"eid": _check(r"\d{1,32}", a.eid, "--eid (digits)") if a.eid else "",
                "pageParam": {"pageNum": page, "pageSize": a.page_size}}
    return _run_list(ctx, path=portal.PATH_BLOCK_LIST, what="block list", body=body, columns=cols,
                     noun="blocked EIDs", narrow="--eid")


def cmd_portal_eid_pushes(ctx: Ctx) -> int:
    obj = _read(ctx, portal.PATH_EVENT_PROFILE_QUERY, {})
    cols = [("created", _time_col("createTime")), ("eid", _col("eid")), ("iccid", _col("iccid")),
            ("status", _col("status")), ("activation code", _col("ac"))]
    return _run_array(ctx, obj=obj, what="EID push list", columns=cols, noun="EID pushes", reveal=ctx.args.reveal_ac)


def cmd_portal_enums(ctx: Ctx) -> int:
    unknown = [n for n in ctx.args.names if n not in ENUM_NAMES]
    if unknown:
        raise UsageError(f"unknown enum name {unknown[0]!r}; choose from: {', '.join(ENUM_NAMES)}")
    names = list(ctx.args.names) or list(ENUM_NAMES)
    obj = _need_dict(_read(ctx, portal.PATH_ENUM_LIST, {"enumNames": names}), "enum list")
    view = sanitize(obj, ctx.redactor)
    if ctx.args.json:
        ctx.show_json(view)
    else:
        import json as _json
        ctx.say(kv([(k, clean(_json.dumps(v, ensure_ascii=False), 200)) for k, v in view.items()]) if view
                else "The portal returned no enum values.")
    return EXIT_OK


# ------------------------------------------------------------------ dashboard / analytics / report

def cmd_portal_stats(ctx: Ctx) -> int:
    pct = _need_dict(_read(ctx, portal.PATH_ANALYTIC_PERCENTAGE, {}), "dashboard counts")
    status = _need_dict(_read(ctx, portal.PATH_ANALYTIC_PROFILE_STATUS, {}), "profile status counts")
    brand = _need_dict(_read(ctx, portal.PATH_ANALYTIC_DEVICE_BRAND, {}), "device brand counts")
    count = _need_dict(_read(ctx, portal.PATH_ANALYTIC_AC_COUNT, {}), "AC count")
    week = _need_dict(_read(ctx, portal.PATH_ANALYTIC_LATEST_WEEK, {}), "last-week counts")
    if ctx.args.json:
        ctx.show_json(sanitize({"percentage": pct, "profileStatus": status, "deviceBrand": brand,
                                "acCount": count, "latestWeek": week}, ctx.redactor))
        return EXIT_OK

    def card(name: str) -> str:
        value = pct.get(name)
        return _count_of(("count", value.get("count")), ("percentage", value.get("percentage"))) if isinstance(value, dict) else ""
    ctx.say(kv([("Downloads today", card("todayDownload")), ("Downloads this month", card("monthDownload")),
                ("Available today", card("todayAvailable")), ("Profiles generated", count.get("acCount")),
                ("Last 7 days", _count_of(("downloads", week.get("downloads")), ("profiles", week.get("profileCount"))))]))
    statuses = [r for r in status.get("datas", []) if isinstance(r, dict)] if isinstance(status.get("datas"), list) else []
    if statuses:
        ctx.say("\nProfiles by status:")
        ctx.say(table(["status", "profiles"], [(r.get("status"), r.get("count")) for r in statuses]))
    brands = [r for r in brand.get("datas", []) if isinstance(r, dict)] if isinstance(brand.get("datas"), list) else []
    if brands:
        ctx.say("\nDownloads by device brand:")
        ctx.say(table(["brand", "downloads"], [(r.get("deviceName"), r.get("total")) for r in brands]))
    ctx.say("\n" + STATUS_CAVEAT)
    return EXIT_OK


def _month_floor(d: date) -> date:
    return d.replace(day=1)


def _ms(moment: datetime) -> str:
    return str(int(moment.astimezone().timestamp() * 1000))


def _parse_day(text: str, flag: str) -> date:
    try:
        return datetime.strptime(text.strip(), "%Y-%m-%d").date()
    except ValueError:
        raise UsageError(f"{flag}: expected YYYY-MM-DD") from None


def _window(ctx: Ctx, by: str) -> dict[str, str]:
    """startTime / endTime for the dashboard charts, in local time as the portal builds them."""
    a = ctx.args
    today = date.today()
    if by == "day":
        since = _parse_day(a.since, "--since") if a.since else today - timedelta(days=30)
        until = _parse_day(a.until, "--until") if a.until else today
        start = datetime.combine(since, datetime.min.time())
        end = datetime.combine(until, datetime.max.time()).replace(microsecond=999000)
    else:
        until_d = _parse_day(a.until, "--until") if a.until else today
        since_d = _parse_day(a.since, "--since") if a.since else date(today.year - 1, today.month, 1)
        since = _month_floor(since_d)
        until = until_d.replace(day=calendar.monthrange(until_d.year, until_d.month)[1])
        start = datetime.combine(since, datetime.min.time())
        end = datetime.combine(until, datetime.max.time()).replace(microsecond=999000)
    if start > end:
        raise UsageError("--since is after --until")
    return {"startTime": _ms(start), "endTime": _ms(end)}


def cmd_portal_downloads(ctx: Ctx) -> int:
    by = ctx.args.by
    path = portal.PATH_ANALYTIC_DOWNLOAD_BY_DAY if by == "day" else portal.PATH_ANALYTIC_DOWNLOAD_BY_MONTH
    obj = _need_dict(_read(ctx, path, _window(ctx, by)), "download trend")
    rows = _list_in(obj, "datas", "download trend")
    if ctx.args.json:
        ctx.show_json(sanitize(obj, ctx.redactor))
        return EXIT_OK
    ctx.say(table(["date (UTC)", "success", "total", "success rate"],
                  [(_when(r.get("date")), r.get("success"), r.get("total"), r.get("percentage")) for r in rows])
            if rows else "No download data in that range.")
    ctx.say(f"\n{len(rows)} {by}s. Dates are as the portal sends them (epoch milliseconds shown as UTC).")
    return EXIT_OK


def cmd_portal_redownloads(ctx: Ctx) -> int:
    obj = _need_dict(_read(ctx, portal.PATH_ANALYTIC_REDOWNLOAD, _window(ctx, "month")), "re-download trend")
    rows = _list_in(obj, "datas", "re-download trend")
    if ctx.args.json:
        ctx.show_json(sanitize(obj, ctx.redactor))
        return EXIT_OK
    ctx.say(table(["month (UTC)", "installed", "re-downloads"],
                  [(_when(r.get("date")), r.get("installedTimes"), r.get("reDownloadTimes")) for r in rows])
            if rows else "No data in that range.")
    ctx.say(f"\n{len(rows)} months.")
    return EXIT_OK


def cmd_portal_report(ctx: Ctx) -> int:
    a = ctx.args
    day = _parse_day(a.date, "--date") if a.date else date.today() - timedelta(days=1)
    statuses = list(dict.fromkeys(a.status)) if a.status else list(DEFAULT_REPORT_STATUSES)
    body: dict[str, Any] = {"configId": _resolve_config(ctx, a.config) if a.config else "",
                            "profileStatus": statuses, "date": day.strftime("%Y/%m/%d")}
    rows = _need_list(_read(ctx, portal.PATH_REPORT_CONFIG_QUERY, body), "report")
    if a.json:
        ctx.show_json(sanitize(rows, ctx.redactor))
        return EXIT_OK
    headers = ["configuration", "total"] + [s.lower() for s in statuses]
    ctx.say(table(headers, [[r.get("configName"), r.get("totalCount")] + [r.get(f"{s.lower()}Count") for s in statuses]
                            for r in rows]) if rows else f"No report rows for {day.isoformat()}.")
    ctx.say(f"\nReport for {day.isoformat()} ({len(rows)} configurations). " + STATUS_CAVEAT)
    return EXIT_OK


# ------------------------------------------------------------------ plan, orders, account

def cmd_portal_subscription(ctx: Ctx) -> int:
    obj = _read(ctx, portal.PATH_PLAN_QUERY_ORDER, {})
    view = _kv_view(ctx, obj, "subscription")
    if ctx.args.json:
        ctx.show_json(view)
        return EXIT_OK
    for key in ("expiredTime",):
        if key in view:
            view[key] = _when(view[key])
    ctx.say(kv(_flat_pairs(view)))
    return EXIT_OK


def cmd_portal_plans(ctx: Ctx) -> int:
    obj = _need_dict(_read(ctx, portal.PATH_PLAN_LIST, {}), "plan list")
    plans = _list_in(obj, "plans", "plan list")
    if ctx.args.json:
        ctx.show_json(sanitize(obj, ctx.redactor))
        return EXIT_OK
    rows = []
    for plan in plans:
        records = plan.get("records") if isinstance(plan.get("records"), list) else []
        tiers = "; ".join(f"{r.get('downloadTimes')} downloads: {r.get('price')}" for r in records if isinstance(r, dict))
        rows.append((plan.get("planType"), plan.get("level"), clean(tiers, 120)))
    ctx.say(table(["plan", "level", "price tiers (as the portal sends them)"], rows) if rows else "No plans found.")
    return EXIT_OK


def cmd_portal_orders(ctx: Ctx) -> int:
    a = ctx.args
    cols = [("order", _col("orderId")), ("plan", _col("planType", "service")), ("downloads", _col("downloadTimes", "quantity")),
            ("type", _col("orderType")), ("amount", _col("paidAmount")), ("status", _col("status")),
            ("pay", _col("payModel")), ("created", _time_col("createTime")), ("expires", _time_col("expireTime"))]
    return _run_list(ctx, path=portal.PATH_ORDER_LIST, what="order list",
                     body=lambda page: {"pageParam": {"pageNum": page, "pageSize": a.page_size}}, columns=cols,
                     noun="orders", narrow="none available")


def cmd_portal_order(ctx: Ctx) -> int:
    order_id = _check(r"[A-Za-z0-9_-]{1,64}", ctx.args.order_id, "order id")
    obj = _read(ctx, portal.PATH_ORDER_DETAIL, {"orderId": order_id})
    view = _kv_view(ctx, obj, "order detail")
    if ctx.args.json:
        ctx.show_json(view)
    else:
        ctx.say(kv(_flat_pairs(view)))
    return EXIT_OK


def cmd_portal_account(ctx: Ctx) -> int:
    info = _kv_view(ctx, _read(ctx, portal.PATH_ENTERPRISE_INFO, {}), "enterprise info")
    accounts = _need_list(_read(ctx, portal.PATH_ENTERPRISE_LIST, {}), "enterprise list")
    acc_view = sanitize(accounts, ctx.redactor)
    if ctx.args.json:
        ctx.show_json({"enterprise": info, "accounts": acc_view})
        return EXIT_OK
    ctx.say(kv(_flat_pairs(info)) or "The portal returned no enterprise details.")
    if acc_view:
        ctx.say("\nAccounts you can switch to (this tool does not switch accounts):")
        ctx.say(table(["client id", "name", "partner", "billable downloads"],
                      [(r.get("clientId"), r.get("name"), r.get("partner"), r.get("downloadTimes")) for r in acc_view]))
    return EXIT_OK


# ------------------------------------------------------------------ summary

def cmd_portal_summary(ctx: Ctx) -> int:
    a = ctx.args
    filters = _fleet_filters(ctx)
    if a.config:
        filters["configId"] = _resolve_config(ctx, a.config)
    obj, rows, total, pages, stop = _fetch_fleet(ctx, filters)
    _paging_warnings(ctx, True, rows, total, stop, "--status, --since, --until, --config")
    facts = _paging_facts(pages, stop, rows, total)
    counted = [r for r in rows if str(r.get("createBy", "")).lower() != "demo"]
    demo = len(rows) - len(counted)
    if a.include_demo:
        counted, demo = rows, 0
    by_status: dict[str, int] = {}
    by_config: dict[str, dict[str, int]] = {}
    for r in counted:
        st = normalize_status(r.get("status")) or "(none)"
        cfg = _pick(r, "configName", "configurationName", "config")
        cfg = str(cfg) if cfg not in (None, "") else (f"configId {r['configId']}" if r.get("configId") not in (None, "") else "(none)")
        by_status[st] = by_status.get(st, 0) + 1
        by_config.setdefault(cfg, {})
        by_config[cfg][st] = by_config[cfg].get(st, 0) + 1
    on_phone = sum(by_status.get(s, 0) for s in ON_PHONE_STATUSES)
    result = {
        "counted": len(counted), "demoExcluded": demo, "portalTotal": total,
        "byStatus": dict(sorted(by_status.items())),
        "byConfiguration": {c: {"total": sum(m.values()), "byStatus": dict(sorted(m.items()))}
                            for c, m in sorted(by_config.items())},
        "onOrPossiblyOnPhone": on_phone, **facts,
    }
    if a.json:
        ctx.show_json(sanitize(result, ctx.redactor))
    else:
        statuses = sorted(by_status)
        if counted:
            ctx.say("By status:")
            ctx.say(table(["status", "profiles", "meaning"], [(s, by_status[s], status_meaning(s)) for s in statuses]))
            ctx.say("\nBy configuration:")
            ctx.say(table(["configuration", "total"] + statuses,
                          [[c, sum(m.values())] + [m.get(s, "") for s in statuses] for c, m in sorted(by_config.items())]))
        else:
            ctx.say("No profiles found.")
        ctx.say(f"\n{len(counted)} profiles counted"
                + (f" ({demo} demo rows excluded; --include-demo counts them)" if demo else "")
                + (f"; the portal reports a total of {total}" if total is not None else "")
                + (", list complete" if facts["complete"] is True else ", completeness unknown" if facts["complete"] is None
                   else ", list INCOMPLETE") + f" ({pages} page{'s' if pages != 1 else ''} fetched).")
        ctx.say(f"On, or possibly on, a phone (DOWNLOADED + INSTALLED + ENABLED + DISABLED): {on_phone}.")
        ctx.say(STATUS_CAVEAT)
    if a.strict and facts["complete"] is False:
        ctx.warn("error: --strict: the list is known to be incomplete (see the warning above).")
        return EXIT_FAIL
    return EXIT_OK


# ------------------------------------------------------------------ QR image (a read that yields a bearer secret)

def write_private_bytes(path: str, data: bytes) -> None:
    """Write `data` to a mode 0600 file. Refuses symlinks and devices (such as stdout)."""
    if path.strip() in ("", "-") or os.path.realpath(path).startswith(("/dev/", "/proc/")):
        raise UsageError("--out must be an ordinary file: the QR code is a bearer secret and is not written to stdout")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError as err:
        raise ConfigError(f"could not write {path} ({type(err).__name__})") from None


def cmd_portal_qr(ctx: Ctx) -> int:
    a = ctx.args
    iccid = iccid_arg(a.iccid)
    if not a.reveal_ac:
        raise UsageError("a QR code is an activation code as a picture, a bearer secret: add --reveal-ac to "
                         "write it to --out FILE (mode 0600). It is not printed.")
    if not a.out:
        raise UsageError("--out FILE is required (the QR image is written to a private file, not stdout)")
    if a.out.strip() in ("-",) or os.path.realpath(a.out).startswith(("/dev/", "/proc/")):
        raise UsageError("--out must be an ordinary file: the QR code is a bearer secret and is not written to stdout")
    row = find_profile(ctx, iccid)
    code = _pick(row, "ac", "acString", "activationCode")
    if not isinstance(code, str) or not code.strip():
        raise SimlesslyError("the portal's fleet row has no activation code for this profile", kind="api")
    ctx.redactor.add(code.strip())
    payload = code.strip()
    if not payload.upper().startswith("LPA:"):
        payload = "LPA:" + payload
    png = portal_cli._client(ctx, portal_cli._stored_token(ctx)).read_bytes(portal.PATH_FLEET_QRCODE, {"ac": payload})
    write_private_bytes(a.out, png)
    if a.json:
        ctx.show_json({"iccid": iccid, "file": a.out, "bytes": len(png), "mode": "0600"})
    else:
        ctx.say(f"wrote the QR code for {iccid} to {a.out} ({len(png)} bytes, mode 0600)")
    ctx.warn("warning: the QR code is a bearer secret. Anyone who can scan it can install that eSIM.")
    return EXIT_OK


# ------------------------------------------------------------------ parser

def _since_until(p, what: str = "on or after") -> None:
    p.add_argument("--since", metavar="DATE", help=f"{what}: YYYY-MM-DD (local) or an ISO-8601 time")
    p.add_argument("--until", metavar="DATE", help="on or before: YYYY-MM-DD (end of day) or an ISO-8601 time")


def register(s, leaf) -> None:
    """Add the read-only commands to the `portal` group."""
    p = leaf(s, "profile", "one profile: status, notes, group, recycle state, timeline",
             cmd_portal_profile)
    p.add_argument("iccid")
    p.add_argument("--reveal-ac", action="store_true", help="show the activation code in full")

    p = leaf(s, "log-detail", "device details behind one profile-log row", cmd_portal_log_detail)
    p.add_argument("log_id", metavar="LOG_ID", help="the `log id` column of `simlessly portal logs`")

    p = leaf(s, "batch-logs", "generate and re-generate batch tasks, like Logs > Generate AC", cmd_portal_batch_logs)
    p.add_argument("--type", choices=BATCH_TYPES, help="only this kind of task")
    p.add_argument("--process", choices=("COMPLETE", "PROCESSING"), help="only finished or running tasks")
    p.add_argument("--format", choices=("STRING", "PICTURE", "AC_LINK"), help="only tasks that produced this AC format")
    _since_until(p, "created on or after")
    add_paging(p)
    p.add_argument("--reveal-ac", action="store_true", help="show links to the generated AC files in full (error-report links stay masked)")

    p = leaf(s, "recycle-logs", "recycle log, like Logs > Recycle", cmd_portal_recycle_logs)
    p.add_argument("--iccid", help="only this ICCID (digits)")
    p.add_argument("--order-id", help="only this order id")
    _since_until(p)
    add_paging(p)

    p = leaf(s, "recycle-status", "recycle state of one or more profiles", cmd_portal_recycle_status)
    p.add_argument("iccids", nargs="+", metavar="ICCID")

    p = leaf(s, "campaigns", "list campaigns", cmd_portal_campaigns)
    p.add_argument("--page", type=portal_cli.page_arg, default=None, help="page number, 1-10000 (default 1)")
    p.add_argument("--page-size", type=portal_cli.page_size_arg, default=portal_cli.DEFAULT_PAGE_SIZE,
                   help=f"rows per page, 1-200 (default {portal_cli.DEFAULT_PAGE_SIZE})")
    p.add_argument("--all", action="store_true", help="fetch every page")
    p.add_argument("--strict", action="store_true", help="with --all: exit 1 when the list is known to be incomplete")
    p.add_argument("--reveal-ac", action="store_true", help="show the campaign activation codes in full")

    p = leaf(s, "campaign-profiles", "profiles inside one campaign", cmd_portal_campaign_profiles)
    p.add_argument("campaign_id", metavar="CAMPAIGN_ID")
    p.add_argument("--iccid", help="only this ICCID (digits)")
    p.add_argument("--eid", help="only this EID (digits)")
    add_paging(p)
    p.set_defaults(reveal_ac=False)

    leaf(s, "groups", "list profile groups", cmd_portal_groups)

    p = leaf(s, "configs", "list profile configurations with their ids", cmd_portal_configs)
    p.add_argument("--name", help="filter by name")
    add_paging(p)
    p = leaf(s, "config", "one configuration in full", cmd_portal_config)
    p.add_argument("config_id", metavar="CONFIG_ID")

    p = leaf(s, "blocks", "blocked EIDs", cmd_portal_blocks)
    p.add_argument("--eid", help="only this EID (digits)")
    add_paging(p)

    p = leaf(s, "eid-pushes", "previous EID pushes", cmd_portal_eid_pushes)
    p.add_argument("--reveal-ac", action="store_true", help="show activation codes in full")

    p = leaf(s, "enums", "the portal's enum values (statuses, config types)", cmd_portal_enums)
    # Names are checked in cmd_portal_enums: Python 3.11's argparse rejects an empty nargs="*" list with choices.
    p.add_argument("names", nargs="*", metavar="NAME",
                   help="any of: " + ", ".join(ENUM_NAMES) + " (default: all)")

    leaf(s, "stats", "dashboard numbers: downloads, profiles by status, device brands", cmd_portal_stats)
    p = leaf(s, "downloads", "download trend by day or month, like the dashboard chart", cmd_portal_downloads)
    p.add_argument("--by", choices=("day", "month"), default="day", help="bucket size (default day: the last 30 days)")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p = leaf(s, "redownloads", "installs versus re-downloads by month", cmd_portal_redownloads)
    p.add_argument("--since", metavar="YYYY-MM-DD", help="default: 12 months back")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p = leaf(s, "report", "profile counts per configuration for one day, like the Report page", cmd_portal_report)
    p.add_argument("--date", metavar="YYYY-MM-DD", help="default: yesterday")
    p.add_argument("--config", metavar="NAME_OR_ID", help="only this configuration (name or configId)")
    p.add_argument("--status", action="append", choices=PROFILE_STATUSES, metavar="STATUS",
                   help="count this status (repeatable; default: " + ", ".join(DEFAULT_REPORT_STATUSES) + ")")

    leaf(s, "subscription", "the current plan and download allowance", cmd_portal_subscription)
    leaf(s, "plans", "available plans and price tiers", cmd_portal_plans)
    p = leaf(s, "orders", "list orders", cmd_portal_orders)
    add_paging(p)
    p = leaf(s, "order", "one order in full", cmd_portal_order)
    p.add_argument("order_id", metavar="ORDER_ID")
    leaf(s, "account", "account details and the accounts you can switch to", cmd_portal_account)

    p = leaf(s, "summary", "profile counts by status and configuration (walks the whole fleet)",
             cmd_portal_summary)
    p.add_argument("--config", metavar="NAME_OR_ID", help="only this configuration (name or configId)")
    p.add_argument("--status", help="only this status, sent as given")
    _since_until(p, "created on or after")
    p.add_argument("--page-size", type=portal_cli.page_size_arg, default=200, help="rows per page, 1-200 (default 200)")
    p.add_argument("--include-demo", action="store_true", help="also count demo rows (default: excluded)")
    p.add_argument("--strict", action="store_true", help="exit 1 when the walk is known to be incomplete")
    p.set_defaults(all=True, page=None, iccid=None, msisdn=None, csv=None, reveal_ac=False)

    p = leaf(s, "qr", "write one profile's QR code as a PNG to a private file (needs --reveal-ac)", cmd_portal_qr)
    p.add_argument("iccid")
    p.add_argument("--out", metavar="FILE", help="where to write the PNG (mode 0600; never stdout)")
    p.add_argument("--reveal-ac", action="store_true", help="confirm writing the QR code, which is a secret")
