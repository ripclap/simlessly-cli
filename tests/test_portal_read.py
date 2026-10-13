"""The read-only portal commands against the local mock portal. The mock enforces each path's method
and answers a wrong one with HTTP 200 / code 10008, like the live portal."""

import contextlib
import io
import json
import os
import stat
import unittest
from urllib.parse import parse_qs

import support
from support import AC, EID, envelope, ok
from simlessly_cli import portal
from test_portal import EXPIRED_MESSAGE, POSIX, TOKEN, PortalCase, bad_session, paged, row

ICCID = "8999000000000000001"
PNG = portal.PNG_MAGIC + b"fake-png-bytes"
IMSI_RUN = "001010000000009"


def prow(**extra):
    """A fleet row for ICCID with the extra fields `portal profile` shows."""
    r = row(1, iccid=ICCID, id=4242, status="ENABLED", groupName="pilot", notes="ward 7", configType="Regular",
            ac=AC, acLink="https://static.simlessly.com/qr/secret-link-9999.png", smdp="rsp.simlessly.com",
            clientIp="203.0.113.9", brand="Pixel", createBy="alice")
    r.update(extra)
    return r


class ReadCase(PortalCase):
    def setUp(self):
        super().setUp()
        self.signed_in()

    def route(self, path, obj):
        """Serve `obj` at `path` (needs the session token); returns the requests seen there."""
        seen = []

        def handler(rec):
            if rec.headers.get("Simlessly-Token") != TOKEN:
                return bad_session()(rec)
            seen.append(rec)
            return ok(obj(rec) if callable(obj) else obj)
        self.server.routes[path] = handler
        return seen

    def assertMethodsRespected(self):
        for rec in self.server.requests:
            self.assertEqual(rec.method, portal.PORTAL_METHODS[rec.path], rec.path)
            self.assertEqual(rec.problems, [], rec.path)
            self.assertIn(rec.path, portal.READ_PATHS)

    def run_ok(self, *argv):
        code, out, err = self.run_cli("portal", *argv)
        self.assertEqual(code, 0, err)
        self.assertClean(out, err)
        self.assertNotIn("unofficial", (out + err).lower())
        return out, err

    @staticmethod
    def body(rec):
        return json.loads(rec.body)


# ------------------------------------------------------------------ profile / log detail

class ProfileTests(ReadCase):
    def serve(self, rows=None, recycle=None, tx=None):
        self.fleet = self.route("/api/v1/fleet/list", {"pageData": rows if rows is not None else [prow()],
                                                      "pageParam": {"total": 1}})
        self.recycle = self.route("/api/v1/fleet/recycle/query", recycle if recycle is not None else [
            {"iccid": ICCID, "status": "AWAITING", "estimatedTime": 1790812800000, "recycledReason": "", "received": True}])
        self.tx = self.route("/api/v1/fleet/transaction", tx if tx is not None else {
            "pageData": [{"createTime": 1790812900000, "iccid": ICCID, "status": "ENABLED", "reason": "", "operator": "device"}],
            "pageParam": {"total": 3}})

    def test_the_three_read_calls_and_the_masked_view(self):
        self.serve()
        out, err = self.run_ok("profile", ICCID)
        self.assertEqual(self.fleet[0].body, '{"iccid":"%s","iccidList":"","status":"","configId":"","startTime":"","endTime":"",'
                                              '"groupId":"","recycleStatus":"","acString":"","msisdn":"",'
                                              '"pageParam":{"pageNum":1,"pageSize":20}}' % ICCID)
        self.assertEqual(self.recycle[0].body, '{"iccid":["%s"]}' % ICCID)
        self.assertEqual(self.tx[0].body, '{"iccid":"%s"}' % ICCID)
        for text in ("4242", "ENABLED", "pilot", "ward 7", "Pixel", "AWAITING", "Recycle state", "Status timeline",
                     "3 transactions", "not proof an eSIM left a phone"):
            self.assertIn(text, out.replace("1 of 3 transactions shown", "3 transactions"))
        for secret in (AC, EID, "secret-link-9999", row(1)["imsi"]):
            self.assertNotIn(secret, out)
        self.assertIn("****" + EID[-4:], out)
        self.assertMethodsRespected()

    def test_reveal_ac_shows_only_the_code_and_warns(self):
        self.serve()
        code, out, err = self.run_cli("portal", "profile", ICCID, "--reveal-ac")
        self.assertEqual(code, 0)
        self.assertIn(AC, out)
        self.assertNotIn(EID, out)
        self.assertIn("bearer secret", err)

    def test_json_is_masked_and_complete(self):
        self.serve()
        out, err = self.run_ok("profile", ICCID, "--json")
        data = json.loads(out)
        self.assertEqual(set(data), {"profile", "recycle", "transactions"})
        self.assertEqual(data["profile"]["notes"], "ward 7")
        self.assertEqual(data["profile"]["eid"], "****" + EID[-4:])
        self.assertEqual(data["transactions"]["total"], 3)
        self.assertNotIn(AC, out)

    def test_only_the_exact_iccid_is_taken_and_a_missing_one_is_an_error(self):
        self.serve(rows=[prow(iccid=ICCID + "9"), prow(iccid="8999000000000000002")])
        code, out, err = self.run_cli("portal", "profile", ICCID)
        self.assertEqual(code, 1)
        self.assertIn("no profile with ICCID", err)
        self.assertEqual(self.recycle, [])

    def test_bad_iccid_makes_no_call(self):
        self.serve()
        code, out, err = self.run_cli("portal", "profile", "123")
        self.assertEqual(code, 2)
        self.assertEqual(self.server.requests, [])

    def test_free_text_imsi_runs_are_masked(self):
        self.serve(rows=[prow(notes=f"sim {IMSI_RUN} here")])
        out, err = self.run_ok("profile", ICCID)
        self.assertNotIn(IMSI_RUN, out)


class LogDetailTests(ReadCase):
    def test_get_query_and_masking(self):
        seen = self.route("/api/v1/log/profile/detail", {"eid": EID, "ip": "203.0.113.9", "brand": "Apple",
                                                         "deviceType": "iPhone", "deviceName": "Test phone"})
        out, err = self.run_ok("log-detail", "12345")
        self.assertEqual((seen[0].method, seen[0].query, seen[0].body), ("GET", "id=12345", ""))
        self.assertIn("Test phone", out)
        self.assertNotIn(EID, out)
        self.assertIn("****" + EID[-4:], out)
        out, err = self.run_ok("log-detail", "12345", "--json")
        self.assertEqual(json.loads(out)["eid"], "****" + EID[-4:])

    def test_bad_id_makes_no_call(self):
        code, out, err = self.run_cli("portal", "log-detail", "1;drop")
        self.assertEqual(code, 2)
        self.assertEqual(self.server.requests, [])


class LogsExtraTests(ReadCase):
    def test_filters_and_all(self):
        rows = [{"id": i, "createTime": 1790812800000 + i, "iccid": ICCID, "status": "DELETED", "reason": "", "operator": "device",
                 "eid": EID} for i in range(1, 6)]
        log = []
        self.server.routes["/api/v1/log/profile/list"] = paged(rows, log=log)
        code, out, err = self.run_cli("portal", "logs", "--all", "--page-size", "2", "--status", "DELETED",
                                      "--since", "2026-10-01T00:00:00+00:00", "--until", "2026-10-02T00:00:00+00:00", "--json")
        data = json.loads(out)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual([b["pageParam"]["pageNum"] for b in log], [1, 2, 3])
        self.assertEqual(len(data["pageData"]), 5)
        self.assertEqual((data["complete"], data["truncated"], data["stopReason"]), (True, False, "total-reached"))
        self.assertEqual(log[0]["status"], "DELETED")
        self.assertEqual(log[0]["startTime"], "1790812800000")
        self.assertEqual(self.sleeps, [0.5, 0.5])
        code, out, err = self.run_cli("portal", "logs", "--all", "--page", "2")
        self.assertEqual(code, 2)
        code, out, err = self.run_cli("portal", "logs", "--since", "2026-10-05", "--until", "2026-10-01")
        self.assertEqual(code, 2)

    def test_table_has_the_log_id_column(self):
        self.server.routes["/api/v1/log/profile/list"] = paged([{"id": 991, "iccid": ICCID, "status": "ENABLED"}])
        code, out, err = self.run_cli("portal", "logs")
        self.assertIn("log id", out)
        self.assertIn("991", out)
        self.assertIn("log-detail", out)


# ------------------------------------------------------------------ batch / recycle logs, recycle status

class BatchAndRecycleTests(ReadCase):
    TASK = {"type": "RE_GENERATE", "acFormat": "AC_STRING,AC_PICTURE", "process": "COMPLETE", "total": 10, "processed": 10,
            "succeed": 8, "configuration": "demo-config", "createTime": 1790812800000, "endTime": 1790812900000,
            "createBy": "admin", "acUrl": "https://files.simlessly.com/ac/secret-file-7777.csv",
            "resultUrl": "https://files.simlessly.com/err/report-8888.csv"}

    def test_batch_logs_body_table_and_masked_links(self):
        seen = self.route("/api/v1/log/batch-task/list", {"pageData": [self.TASK, {**self.TASK, "process": "PROCESSING",
                                                                                    "processed": 4, "acUrl": "", "resultUrl": ""}],
                                                          "pageParam": {"total": 2}})
        out, err = self.run_ok("batch-logs", "--type", "RE_GENERATE", "--process", "COMPLETE", "--format", "STRING",
                               "--since", "2026-10-01T00:00:00+00:00", "--until", "2026-10-02T00:00:00+00:00")
        self.assertEqual(json.loads(seen[0].body), {
            "type": "RE_GENERATE", "process": "COMPLETE", "acFormat": "STRING", "startTime": "1790812800000",
            "endTime": json.loads(seen[0].body)["endTime"], "pageParam": {"pageNum": 1, "pageSize": 50}})
        self.assertRegex(json.loads(seen[0].body)["endTime"], r"^\d{13}$")
        self.assertEqual(seen[0].method, "POST")
        self.assertIn("8/10", out)                                   # succeed/total when finished
        self.assertIn("4/10", out)                                   # processed/total while PROCESSING
        self.assertIn("2 batch tasks shown of 2", out)
        self.assertNotIn("secret-file-7777", out)
        out, err = self.run_ok("batch-logs", "--json")
        self.assertNotIn("secret-file-7777", out)
        self.assertNotIn("report-8888", out)
        self.assertEqual(json.loads(seen[1].body)["startTime"], "")
        self.assertNotIn("endTime", json.loads(seen[1].body))        # omitted when unset
        code, out, err = self.run_cli("portal", "batch-logs", "--reveal-ac", "--json")
        self.assertIn("secret-file-7777", out)                       # the AC file link only
        self.assertNotIn("report-8888", out)
        self.assertIn("bearer secrets", err)
        code, out, err = self.run_cli("portal", "batch-logs", "--reveal-ac")
        self.assertIn("error-report link always stays masked", out)

    def test_batch_logs_choices_are_validated_locally(self):
        for argv in (["--type", "NOPE"], ["--process", "x"], ["--format", "x"]):
            code, out, err = self.run_cli("portal", "batch-logs", *argv)
            self.assertEqual(code, 2)
        self.assertEqual(self.server.requests, [])

    def test_recycle_logs(self):
        seen = self.route("/api/v1/log/recycle/list", {"pageData": [
            {"iccid": ICCID, "orderId": "O-1", "recycleStatus": "Success", "recycleReason": "", "recycleTime": 1790812800000}],
            "pageParam": {"total": 1}})
        out, err = self.run_ok("recycle-logs", "--iccid", ICCID, "--order-id", "O-1")
        self.assertEqual(json.loads(seen[0].body), {"iccid": ICCID, "orderId": "O-1", "startTime": "",
                                                    "pageParam": {"pageNum": 1, "pageSize": 50}})
        self.assertIn("Success", out)

    def test_recycle_status_sends_the_iccid_list(self):
        seen = self.route("/api/v1/fleet/recycle/query", [
            {"iccid": ICCID, "status": "AWAITING", "estimatedTime": 1790812800000, "recycledReason": "", "received": False},
            {"iccid": "8999000000000000002", "status": "RECYCLED", "recycledTime": 1790812900000}])
        out, err = self.run_ok("recycle-status", ICCID, "8999000000000000002")
        self.assertEqual(seen[0].body, '{"iccid":["%s","8999000000000000002"]}' % ICCID)
        self.assertIn("AWAITING", out)
        self.assertIn("2 recycle states", out)
        code, out, err = self.run_cli("portal", "recycle-status")
        self.assertEqual(code, 2)


# ------------------------------------------------------------------ campaigns, groups, configs, blocks, pushes, enums

class CatalogueTests(ReadCase):
    def test_campaigns_use_flat_get_params(self):
        seen = self.route("/api/v1/campaign/list", {"pageData": [
            {"campaignId": 5, "campaignName": "Launch", "configurationName": "demo-config", "ac": AC, "availableProfiles": 7,
             "totalProfiles": 9, "status": "IN_PROGRESS"}], "pageParam": {"total": 1}})
        out, err = self.run_ok("campaigns", "--page", "2", "--page-size", "10")
        self.assertEqual((seen[0].method, parse_qs(seen[0].query), seen[0].body), ("GET", {"pageNum": ["2"], "pageSize": ["10"]}, ""))
        self.assertIn("Launch", out)
        self.assertNotIn(AC, out)
        code, out, err = self.run_cli("portal", "campaigns", "--reveal-ac")
        self.assertIn(AC, out)
        self.assertIn("bearer secrets", err)

    def test_campaign_all_walks_flat_pages(self):
        pages = []

        def handler(rec):
            q = parse_qs(rec.query)
            pages.append(q["pageNum"][0])
            n = int(q["pageNum"][0])
            return ok({"pageData": [{"campaignId": n * 10 + i, "campaignName": f"c{n}{i}"} for i in range(2)][:2 if n < 2 else 1],
                       "pageParam": {"total": 3}})
        self.server.routes["/api/v1/campaign/list"] = handler
        code, out, err = self.run_cli("portal", "campaigns", "--all", "--page-size", "2", "--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(pages, ["1", "2"])
        self.assertTrue(json.loads(out)["complete"])

    def test_campaign_profiles_body(self):
        seen = self.route("/api/v1/campaign/resource/list", {"pageData": [
            {"campaignResourceId": 1, "iccid": ICCID, "status": "LOCKED", "eid": EID, "createTime": 1790812800000}],
            "pageParam": {"total": 1}})
        out, err = self.run_ok("campaign-profiles", "5", "--eid", EID)
        self.assertEqual(json.loads(seen[0].body), {"campaignId": 5, "iccid": "", "eid": EID,
                                                    "pageParam": {"pageNum": 1, "pageSize": 50}})
        self.assertNotIn(EID, out)
        self.assertIn("LOCKED", out)

    def test_groups_is_a_bare_array_post(self):
        seen = self.route("/api/v1/group/list", [{"id": 3, "name": "pilot", "count": 12, "note": "first wave"}])
        out, err = self.run_ok("groups")
        self.assertEqual((seen[0].method, seen[0].body), ("POST", "{}"))
        self.assertIn("pilot", out)
        self.assertIn("1 groups.", out)
        out, err = self.run_ok("groups", "--json")
        self.assertEqual(json.loads(out)[0]["id"], 3)

    def test_configs_and_config_detail(self):
        seen = self.route("/api/v1/config/query", {"pageData": [
            {"configId": 77, "configName": "demo-config", "configType": "Regular", "configSubType": "Regular",
             "hplmn": {"plmn": "00101", "rat": "4000"}, "maxDownload": 1, "maxAttempt": 3}], "pageParam": {"total": 1}})
        out, err = self.run_ok("configs", "--name", "demo")
        self.assertEqual(json.loads(seen[0].body), {"pageParam": {"pageNum": 1, "pageSize": 50}, "configName": "demo"})
        self.assertIn("77", out)
        self.assertIn("00101", out)
        detail = self.route("/api/v1/config/detail", {"configId": 77, "configName": "demo-config", "imsi460Whitelist": [IMSI_RUN],
                                                      "bipServiceParam": {"ip": "192.0.2.1", "port": 8080}})
        out, err = self.run_ok("config", "77")
        self.assertEqual((detail[0].method, detail[0].query), ("GET", "configId=77"))
        self.assertIn("192.0.2.1", out)
        self.assertNotIn(IMSI_RUN, out)

    def test_blocks_and_eid_pushes(self):
        seen = self.route("/api/v1/block/list", {"pageData": [{"eid": EID, "iccid": ICCID, "reason": "lost", "createBy": "me",
                                                               "createTime": 1790812800000}], "pageParam": {"total": 1}})
        out, err = self.run_ok("blocks")
        self.assertEqual(json.loads(seen[0].body), {"eid": "", "pageParam": {"pageNum": 1, "pageSize": 50}})
        self.assertNotIn(EID, out)
        pushes = self.route("/api/v1/event/profile/query", [{"eid": EID, "iccid": ICCID, "ac": AC, "status": "PUSHED",
                                                              "createTime": 1790812800000}])
        out, err = self.run_ok("eid-pushes")
        self.assertEqual((pushes[0].method, pushes[0].query), ("GET", ""))
        self.assertNotIn(AC, out)
        self.assertNotIn(EID, out)
        self.assertIn("PUSHED", out)

    def test_enums(self):
        seen = self.route("/api/v1/enum/list", {"profileStatus": ["AVAILABLE", "ENABLED"]})
        out, err = self.run_ok("enums", "profileStatus")
        self.assertEqual(seen[0].body, '{"enumNames":["profileStatus"]}')
        self.assertIn("AVAILABLE", out)
        self.run_ok("enums")
        self.assertEqual(seen[1].body, '{"enumNames":["profileStatus","profileOperationStatus","configTypes"]}')
        code, out, err = self.run_cli("portal", "enums", "bogus")
        self.assertEqual(code, 2)


# ------------------------------------------------------------------ stats, trends, report

class StatsTests(ReadCase):
    def test_stats_makes_five_gets(self):
        self.route("/api/v1/analytic/percentage", {"todayDownload": {"count": 3, "percentage": 0.5},
                                                   "monthDownload": {"count": 30, "percentage": 1.5},
                                                   "todayAvailable": {"count": 7, "percentage": 0.1}})
        self.route("/api/v1/analytic/profileStatus", {"datas": [{"status": "ENABLED", "count": 4}]})
        self.route("/api/v1/analytic/deviceBrand", {"datas": [{"deviceName": "Apple", "total": 9}]})
        self.route("/api/v1/analytic/ac-count", {"acCount": 12})
        self.route("/api/v1/analytic/latest-week", {"downloads": 2, "profileCount": 5})
        out, err = self.run_ok("stats")
        self.assertEqual(len(self.server.requests), 5)
        for rec in self.server.requests:
            self.assertEqual((rec.method, rec.query, rec.body), ("GET", "", ""))
        for text in ("count=3", "Profiles generated", "12", "Apple", "ENABLED"):
            self.assertIn(text, out)
        out, err = self.run_ok("stats", "--json")
        self.assertEqual(json.loads(out)["acCount"], {"acCount": 12})
        self.assertMethodsRespected()

    def test_downloads_day_window_and_month_window(self):
        day = self.route("/api/v1/analytic/downloadByDay", {"datas": [{"date": "1790812800000", "success": 3, "total": 4, "percentage": 0.75}]})
        out, err = self.run_ok("downloads", "--since", "2026-10-01", "--until", "2026-10-03")
        body = json.loads(day[0].body)
        self.assertEqual(set(body), {"startTime", "endTime"})
        self.assertTrue(body["startTime"].isdigit() and body["endTime"].isdigit())
        self.assertEqual((int(body["endTime"]) - int(body["startTime"])) // 1000, 3 * 86400 - 1)   # 3 whole local days (DST aside)
        self.assertIn("0.75", out)
        month = self.route("/api/v1/analytic/downloadByMonth", {"datas": []})
        out, err = self.run_ok("downloads", "--by", "month", "--since", "2026-03-15", "--until", "2026-05-02")
        body = json.loads(month[0].body)
        span = (int(body["endTime"]) - int(body["startTime"])) / 86400000
        self.assertTrue(91 <= span <= 92, span)                                                    # 1 Mar .. 31 May
        self.assertIn("No download data", out)
        code, out, err = self.run_cli("portal", "downloads", "--since", "2026-10-05", "--until", "2026-10-01")
        self.assertEqual(code, 2)
        code, out, err = self.run_cli("portal", "downloads", "--since", "yesterday")
        self.assertEqual(code, 2)

    def test_redownloads_defaults_to_twelve_months(self):
        seen = self.route("/api/v1/analytic/redownload", {"datas": [{"date": "1790812800000", "installedTimes": 5, "reDownloadTimes": 1}]})
        out, err = self.run_ok("redownloads")
        body = json.loads(seen[0].body)
        span = (int(body["endTime"]) - int(body["startTime"])) / 86400000
        self.assertTrue(365 <= span <= 400, span)
        self.assertIn("re-downloads", out)

    def test_report_body(self):
        seen = self.route("/api/v1/report/config/query", [{"configName": "demo-config", "totalCount": 9, "availableCount": 4,
                                                           "enabledCount": 3, "deletedCount": 2}])
        out, err = self.run_ok("report", "--date", "2026-10-12", "--config", "77", "--status", "AVAILABLE", "--status", "ENABLED")
        self.assertEqual(seen[0].body, '{"configId":"77","profileStatus":["AVAILABLE","ENABLED"],"date":"2026/10/12"}')
        self.assertIn("demo-config", out)
        self.run_ok("report")
        body = json.loads(seen[1].body)
        self.assertEqual(seen[1].body, '{"configId":"","profileStatus":["AVAILABLE","ENABLED","DISABLED","DELETED","ERROR"],"date":"%s"}' % body["date"])
        self.assertEqual(body["configId"], "")
        self.assertEqual(body["profileStatus"], ["AVAILABLE", "ENABLED", "DISABLED", "DELETED", "ERROR"])
        self.assertRegex(body["date"], r"^\d{4}/\d{2}/\d{2}$")
        code, out, err = self.run_cli("portal", "report", "--status", "BOGUS")
        self.assertEqual(code, 2)


# ------------------------------------------------------------------ plan, orders, account

class AccountTests(ReadCase):
    def test_subscription_plans_orders(self):
        sub = self.route("/api/v1/plan/queryOrder", {"planType": "PRO", "status": "ACTIVE", "expiredTime": 1790812800000,
                                                     "downloadTotal": 1000, "downloadTimes": 12, "autoRenew": "On"})
        out, err = self.run_ok("subscription")
        self.assertEqual((sub[0].method, sub[0].body), ("POST", "{}"))
        self.assertIn("PRO", out)
        self.assertIn("2026-10-", out)
        self.route("/api/v1/plan/list", {"plans": [{"planType": "BASIC", "level": 1, "records": [{"downloadTimes": 100, "price": 9}]}]})
        out, err = self.run_ok("plans")
        self.assertIn("100 downloads: 9", out)
        orders = self.route("/api/v1/order/list", {"pageData": [{"orderId": "O-9", "planType": "PRO", "downloadTimes": 1000,
                                                                 "orderType": "MONTHLY", "paidAmount": 50, "status": "ACTIVE",
                                                                 "payModel": "STRIPE", "createTime": 1790812800000}],
                                                   "pageParam": {"total": 1}})
        out, err = self.run_ok("orders")
        self.assertEqual(json.loads(orders[0].body), {"pageParam": {"pageNum": 1, "pageSize": 50}})
        self.assertIn("O-9", out)
        detail = self.route("/api/v1/order/detail", {"orderId": "O-9", "amount": 50, "status": "ACTIVE"})
        out, err = self.run_ok("order", "O-9")
        self.assertEqual(detail[0].body, '{"orderId":"O-9"}')
        self.assertIn("ACTIVE", out)

    def test_account_makes_two_gets_and_masks_the_imsi_whitelist(self):
        info = self.route("/api/v1/enterprise/info", {"name": "Acme", "isSub": False, "imsi460Whitelist": [IMSI_RUN]})
        lst = self.route("/api/v1/enterprise/list", [{"clientId": 9, "name": "Acme", "partner": False, "downloadTimes": 3}])
        out, err = self.run_ok("account")
        self.assertEqual((info[0].method, lst[0].method), ("GET", "GET"))
        self.assertIn("Acme", out)
        self.assertNotIn(IMSI_RUN, out)
        self.assertIn("does not switch accounts", out)


# ------------------------------------------------------------------ summary

class SummaryTests(ReadCase):
    def fleet(self, rows, **kw):
        self.log = []
        self.server.routes["/api/v1/fleet/list"] = paged(rows, log=self.log, **kw)

    def test_counts_by_status_and_configuration(self):
        rows = [row(i, status=["AVAILABLE", "ENABLED", "DELETED", "DOWNLOADED"][i % 4],
                    configName=["alpha", "beta"][i % 2]) for i in range(1, 11)]
        rows.append(row(11, status="ENABLED", createBy="demo"))
        self.fleet(rows)
        code, out, err = self.run_cli("portal", "summary", "--json", "--page-size", "4")
        data = json.loads(out)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(data["counted"], 10)
        self.assertEqual(data["demoExcluded"], 1)
        self.assertEqual(sum(data["byStatus"].values()), 10)
        self.assertEqual(sum(c["total"] for c in data["byConfiguration"].values()), 10)
        self.assertEqual(data["onOrPossiblyOnPhone"], data["byStatus"].get("ENABLED", 0) + data["byStatus"].get("DOWNLOADED", 0))
        self.assertTrue(data["complete"])
        self.assertEqual([b["pageParam"]["pageNum"] for b in self.log], [1, 2, 3])
        self.assertEqual(self.sleeps, [0.5, 0.5])
        self.assertIn("alpha", data["byConfiguration"])
        self.assertClean(out)

    def test_table_and_caveat_and_include_demo(self):
        self.fleet([row(1, status="AVAILABLE"), row(2, status="ENABLED", createBy="demo")])
        code, out, err = self.run_cli("portal", "summary")
        self.assertEqual(code, 0, err)
        for text in ("By status:", "By configuration:", "1 profiles counted (1 demo rows excluded", "list complete",
                     "On, or possibly on, a phone", "not proof an eSIM left a phone"):
            self.assertIn(text, out)
        code, out, err = self.run_cli("portal", "summary", "--include-demo", "--json")
        self.assertEqual(json.loads(out)["counted"], 2)

    def test_filters_reach_the_fleet_body(self):
        self.fleet([row(1)])
        self.run_cli("portal", "summary", "--status", "ENABLED", "--config", "77", "--since", "2026-10-01")
        body = self.log[0]
        self.assertEqual((body["status"], body["configId"]), ("ENABLED", "77"))
        self.assertEqual(body["pageParam"]["pageSize"], 200)
        self.assertRegex(body["startTime"], r"^\d{13}$")

    def test_incomplete_walk_is_reported_and_strict_fails(self):
        self.fleet([row(i) for i in range(1, 4)], total=9)           # claims 9, serves 3
        code, out, err = self.run_cli("portal", "summary", "--json", "--page-size", "2")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertIs(data["complete"], False)
        self.assertEqual(data["stopReason"], "short-of-total")
        self.assertIn("not complete", err)
        code, out, err = self.run_cli("portal", "summary", "--strict", "--page-size", "2")
        self.assertEqual(code, 1)
        self.assertIn("INCOMPLETE", out)

    def test_unknown_total_says_so(self):
        self.fleet([row(1)], total=None)
        code, out, err = self.run_cli("portal", "summary")
        self.assertIn("completeness unknown", out)
        self.assertIn("no total", err)


# ------------------------------------------------------------------ qr

class QrTests(ReadCase):
    def setUp(self):
        super().setUp()
        self.out_path = str(self.tmp / "qr.png")
        self.route("/api/v1/fleet/list", {"pageData": [prow()], "pageParam": {"total": 1}})
        self.qr = self.route("/api/v1/fleet/qrcode", lambda rec: None)
        self.server.routes["/api/v1/fleet/qrcode"] = self.qr_route

    def qr_route(self, rec):
        self.qr.append(rec)
        return 200, PNG, {}

    def test_refuses_without_reveal_ac_or_out_and_makes_no_call(self):
        for argv in (["qr", ICCID, "--out", self.out_path], ["qr", ICCID, "--reveal-ac"],
                     ["qr", ICCID, "--reveal-ac", "--out", "-"], ["qr", ICCID, "--reveal-ac", "--out", "/dev/stdout"]):
            code, out, err = self.run_cli("portal", *argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "")
        self.assertEqual(self.server.requests, [])
        self.assertFalse(os.path.exists(self.out_path))

    def test_writes_a_private_png_and_never_prints_it(self):
        code, out, err = self.run_cli("portal", "qr", ICCID, "--reveal-ac", "--out", self.out_path)
        self.assertEqual(code, 0, err)
        with open(self.out_path, "rb") as handle:
            self.assertEqual(handle.read(), PNG)
        if POSIX:
            self.assertEqual(stat.S_IMODE(os.stat(self.out_path).st_mode), 0o600)
        self.assertNotIn("PNG", out)
        self.assertNotIn(AC, out + err)
        self.assertIn("bearer secret", err)
        rec = self.qr[0]
        self.assertEqual((rec.method, json.loads(rec.body)), ("POST", {"ac": "LPA:" + AC}))
        self.assertEqual(rec.headers["Simlessly-Token"], TOKEN)
        self.assertMethodsRespected()

    def test_an_existing_loose_file_is_tightened(self):
        if not POSIX:
            self.skipTest("POSIX permissions")
        with open(self.out_path, "wb") as handle:
            handle.write(b"old")
        os.chmod(self.out_path, 0o644)
        self.run_cli("portal", "qr", ICCID, "--reveal-ac", "--out", self.out_path)
        self.assertEqual(stat.S_IMODE(os.stat(self.out_path).st_mode), 0o600)

    def test_a_symlink_target_is_refused(self):
        if not POSIX:
            self.skipTest("symlinks")
        target = self.tmp / "target"
        target.write_bytes(b"keep")
        os.symlink(target, self.out_path)
        code, out, err = self.run_cli("portal", "qr", ICCID, "--reveal-ac", "--out", self.out_path)
        self.assertEqual(code, 1)
        self.assertEqual(target.read_bytes(), b"keep")

    def test_json_failure_envelope_and_non_png_are_errors(self):
        self.server.routes["/api/v1/fleet/qrcode"] = lambda rec: (200, envelope(None, False, f"bad {AC}", "50000"), {})
        code, out, err = self.run_cli("portal", "qr", ICCID, "--reveal-ac", "--out", self.out_path)
        self.assertEqual(code, 1)
        self.assertNotIn(AC, err)
        self.assertFalse(os.path.exists(self.out_path))
        self.server.routes["/api/v1/fleet/qrcode"] = lambda rec: (200, b"<html>not an image</html>", {})
        code, out, err = self.run_cli("portal", "qr", ICCID, "--reveal-ac", "--out", self.out_path)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out_path))

    def test_expired_session(self):
        self.server.routes["/api/v1/fleet/qrcode"] = bad_session()
        code, out, err = self.run_cli("portal", "qr", ICCID, "--reveal-ac", "--out", self.out_path)
        self.assertEqual((code, err), (1, "error: " + EXPIRED_MESSAGE + "\n"))

    def test_a_row_without_a_code_is_an_error(self):
        self.route("/api/v1/fleet/list", {"pageData": [prow(ac="", acString="")], "pageParam": {"total": 1}})
        code, out, err = self.run_cli("portal", "qr", ICCID, "--reveal-ac", "--out", self.out_path)
        self.assertEqual(code, 1)
        self.assertEqual(self.qr, [])


# ------------------------------------------------------------------ cross-cutting

class EveryReadCommandTests(ReadCase):
    """One table: each read command's argv, the path it must call, and a minimal good answer."""
    CASES = [
        (["profile", ICCID], "/api/v1/fleet/list", {"pageData": [prow()]}),
        (["log-detail", "9"], "/api/v1/log/profile/detail", {"eid": EID}),
        (["batch-logs"], "/api/v1/log/batch-task/list", {"pageData": []}),
        (["recycle-logs"], "/api/v1/log/recycle/list", {"pageData": []}),
        (["recycle-status", ICCID], "/api/v1/fleet/recycle/query", []),
        (["campaigns"], "/api/v1/campaign/list", {"pageData": []}),
        (["campaign-profiles", "5"], "/api/v1/campaign/resource/list", {"pageData": []}),
        (["groups"], "/api/v1/group/list", []),
        (["configs"], "/api/v1/config/query", {"pageData": []}),
        (["config", "7"], "/api/v1/config/detail", {"configId": 7}),
        (["blocks"], "/api/v1/block/list", {"pageData": []}),
        (["eid-pushes"], "/api/v1/event/profile/query", []),
        (["enums"], "/api/v1/enum/list", {}),
        (["stats"], "/api/v1/analytic/percentage", {}),
        (["downloads"], "/api/v1/analytic/downloadByDay", {"datas": []}),
        (["redownloads"], "/api/v1/analytic/redownload", {"datas": []}),
        (["report"], "/api/v1/report/config/query", []),
        (["subscription"], "/api/v1/plan/queryOrder", {}),
        (["plans"], "/api/v1/plan/list", {"plans": []}),
        (["orders"], "/api/v1/order/list", {"pageData": []}),
        (["order", "O-1"], "/api/v1/order/detail", {}),
        (["account"], "/api/v1/enterprise/info", {}),
        (["summary"], "/api/v1/fleet/list", {"pageData": []}),
    ]

    def test_no_session_means_no_call(self):
        os.remove(self.path)
        for argv, _, _ in self.CASES:
            code, out, err = self.run_cli("portal", *argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("simlessly portal login", err)
        self.assertEqual(self.server.requests, [])

    def test_an_expired_session_is_the_same_clear_error_and_is_never_retried(self):
        for argv, path, _ in self.CASES:
            self.server.requests.clear()
            self.server.routes[path] = bad_session("10103")
            code, out, err = self.run_cli("portal", *argv)
            self.assertEqual((code, out, err), (1, "", "error: " + EXPIRED_MESSAGE + "\n"), argv)
            self.assertEqual(len(self.server.requests), 1, argv)

    def test_the_first_call_of_each_command_uses_the_mapped_method_and_token(self):
        for argv, path, obj in self.CASES:
            self.server.requests.clear()
            self.route(path, obj)
            for extra, extra_obj in (("/api/v1/fleet/recycle/query", []), ("/api/v1/fleet/transaction", {}),
                                     ("/api/v1/analytic/profileStatus", {}), ("/api/v1/analytic/deviceBrand", {}),
                                     ("/api/v1/analytic/ac-count", {}), ("/api/v1/analytic/latest-week", {}),
                                     ("/api/v1/enterprise/list", [])):
                self.route(extra, extra_obj)
            code, out, err = self.run_cli("portal", *argv)
            self.assertEqual(code, 0, (argv, err))
            first = self.server.requests[0]
            self.assertEqual(first.path, path, argv)
            self.assertEqual(first.method, portal.PORTAL_METHODS[path], argv)
            self.assertEqual(first.headers["Simlessly-Token"], TOKEN)
            self.assertNotIn("Content-Type", first.headers if first.method == "GET" else {})
            self.assertMethodsRespected()

    def test_api_error_text_is_scrubbed(self):
        for argv, path, _ in self.CASES[:6]:
            self.server.routes[path] = lambda rec: (200, envelope(None, False, f"boom {TOKEN} {AC}", "50000"), {})
            code, out, err = self.run_cli("portal", *argv)
            self.assertEqual(code, 1, argv)
            self.assertClean(out, err)
            self.assertNotIn(AC, err)

    def test_help_has_no_unofficial_label(self):
        words = ["login", "token-set", "logout", "fleet", "logs"] + [argv[0] for argv, _, _ in self.CASES] + [
            "notes", "group-assign", "group-create", "regenerate", "recycle", "delete", "generate-ac", "qr"]
        for argv in [["--help"], ["portal", "--help"]] + [["portal", w, "--help"] for w in words]:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
                from simlessly_cli.cli import build_parser
                build_parser().parse_args(argv)
            self.assertNotIn("unofficial", buf.getvalue().lower(), argv)
            self.assertIn("usage:", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
