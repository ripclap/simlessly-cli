import json

import support
from support import AC, AC_LINK, EID, ICCID, KI, OPC, CliTestCase, ok


def detail(status="AVAILABLE", **extra):
    obj = {"iccid": ICCID, "eid": EID, "imsi": "001010000000001", "status": status, "smdp": "rsp-eu.simlessly.com",
           "activation": "ABCDEF0123456789ABCDEF0123456789", "ac": AC, "acLink": AC_LINK, "group": "g",
           "deviceBrand": "Acme", "ip": "192.0.2.9", "configurationName": "demo-config",
           "configurationType": "Regular", "createTime": "2026-10-01T10:00:00Z", "updateTime": "2026-10-02T10:00:00Z"}
    obj.update(extra)
    return obj


class ConfigCheckTests(CliTestCase):
    def test_reports_sources_without_values(self):
        kc = lambda name: {"secret-key": support.SECRET}.get(name)
        env = {"SIMLESSLY_ACCESS_KEY": support.ACCESS}
        code, out, err = self.run_cli("config", "check", env=env, keychain=kc)
        self.assertEqual(code, 0)
        self.assertIn("set (env)", out)
        self.assertIn("set (keychain)", out)
        self.assertIn("missing (optional)", out)
        self.assertNoSecrets(out, err)
        self.assertEqual(self.server.requests, [])  # config check never touches the network

    def test_missing_credentials_fail(self):
        code, out, _ = self.run_cli("config", "check", env={"SIMLESSLY_NO_KEYCHAIN": "1"})
        self.assertEqual(code, 1)
        self.assertIn("missing", out)

    def test_json_and_flag_source(self):
        code, out, _ = self.run_cli("config", "check", "--json", "--base-url", self.server.url)
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(data["settings"]["base-url"], "set (flag)")
        self.assertNoSecrets(out)

    def test_refused_base_url_is_reported(self):
        code, out, _ = self.run_cli("config", "check", "--base-url", "https://evil.example.com")
        self.assertEqual(code, 1)
        self.assertIn("refused", out)


class ConfigsListTests(CliTestCase):
    def test_list(self):
        self.server.routes["/api/v1/config/list"] = lambda r: ok(
            {"configs": ["alpha", "beta"], "pageParam": {"total": 2, "pageNum": 1, "pageSize": 100}})
        code, out, err = self.run_cli("configs", "list")
        self.assertEqual(code, 0, err)
        self.assertIn("alpha", out)
        self.assertIn("2 shown of 2", out)
        rec = self.server.requests[0]
        self.assertEqual(rec.body, '{"pageParam":{"total":0,"pageNum":1,"pageSize":100}}')
        self.assertAllSigned()
        self.assertNoSecrets(out, err)

    def test_filter_and_json(self):
        self.server.routes["/api/v1/config/list"] = lambda r: ok({"configs": ["alpha"]})
        code, out, _ = self.run_cli("configs", "list", "--name", "alp", "--json")
        self.assertEqual(json.loads(out), {"configs": ["alpha"]})
        self.assertTrue(self.server.requests[0].body.startswith('{"configName":"alp",'))

    def test_wrong_shape_is_error(self):
        self.server.routes["/api/v1/config/list"] = lambda r: ok({"configs": "nope"})
        self.assertEqual(self.run_cli("configs", "list")[0], 1)


class ProfileShowTests(CliTestCase):
    def route(self, obj):
        self.server.routes["/api/v1/profile/detail"] = lambda r: ok(obj)

    def test_available_shows_caveat_and_masks_everything(self):
        self.route(detail("AVAILABLE"))
        code, out, err = self.run_cli("profile", "show", ICCID)
        self.assertEqual(code, 0, err)
        self.assertIn("AVAILABLE", out)
        self.assertIn("not proof the eSIM left the phone", out)
        self.assertIn("****6789", out)       # activation code: last 4 only
        self.assertNotIn(AC, out)
        self.assertNotIn(EID, out)
        self.assertNotIn(AC_LINK, out)
        self.assertNotIn("ABCDEF0123456789ABCDEF0123456789", out)
        self.assertEqual(self.server.requests[0].body, '{"iccid":"%s"}' % ICCID)
        self.assertAllSigned()
        self.assertNoSecrets(out, err)

    def test_every_not_proof_state(self):
        for status in ("EXPIRED", "CANCELED", "REMOVED"):
            self.route(detail(status))
            _, out, _ = self.run_cli("profile", "show", ICCID)
            self.assertIn("not proof the eSIM left the phone", out, status)

    def test_other_states_have_no_caveat(self):
        for status in ("ENABLED", "DELETED", "INSTALLED"):
            self.route(detail(status))
            _, out, _ = self.run_cli("profile", "show", ICCID)
            self.assertNotIn("not proof", out, status)

    def test_reveal_ac(self):
        self.route(detail())
        code, out, err = self.run_cli("profile", "show", ICCID, "--reveal-ac")
        self.assertIn(AC, out)
        self.assertIn("bearer secret", err)
        self.assertNoSecrets(out, err)

    def test_json_is_masked_unless_revealed(self):
        self.route(detail())
        _, out, _ = self.run_cli("profile", "show", ICCID, "--json")
        self.assertNotIn(AC, out)
        self.assertEqual(json.loads(out)["status"], "AVAILABLE")
        _, out, _ = self.run_cli("profile", "show", ICCID, "--json", "--reveal-ac")
        self.assertEqual(json.loads(out)["ac"], AC)

    def test_iccid_with_stray_space_is_trimmed_and_bad_iccid_rejected(self):
        self.route(detail())
        self.assertEqual(self.run_cli("profile", "show", " " + ICCID)[0], 0)
        self.assertEqual(self.server.requests[0].body, '{"iccid":"%s"}' % ICCID)
        code, _, err = self.run_cli("profile", "show", "not-an-iccid")
        self.assertEqual(code, 2)
        self.assertEqual(len(self.server.requests), 1)

    def test_answer_for_other_iccid_is_rejected(self):
        self.route(detail(iccid="8999000000000009999"))
        self.assertEqual(self.run_cli("profile", "show", ICCID)[0], 1)


class ProfileLogTests(CliTestCase):
    def route(self, rows, total=None):
        total = len(rows) if total is None else total
        self.server.routes["/api/v1/profile/log"] = lambda r: ok(
            {"profileLogs": rows, "pageParam": {"pageNum": 1, "pageSize": 100, "total": total}})

    def row(self, status, reason=None, t="10/03/2026, 04:05:06"):
        return {"iccid": ICCID, "eid": EID, "status": status, "reason": reason, "operator": "system", "createTime": t}

    def test_deleted_found(self):
        self.route([self.row("DOWNLOADED"), self.row("DELETE")])
        code, out, err = self.run_cli("profile", "log", ICCID)
        self.assertEqual(code, 0, err)
        self.assertIn("DELETED event: found", out)
        self.assertNotIn(EID, out)
        body = json.loads(self.server.requests[0].body)
        self.assertEqual(body, {"iccid": ICCID, "pageParam": {"pageNum": 1, "pageSize": 100}})
        self.assertAllSigned()

    def test_deleted_verdict_names_the_time_and_cautions_about_unordered_events(self):
        # locale-style times are not ordered, so other on-phone events get a caution
        self.route([self.row("ENABLED", t="10/01/2026, 01:00:00"), self.row("DELETE", t="10/02/2026, 01:00:00")])
        _, out, _ = self.run_cli("profile", "log", ICCID)
        self.assertIn("DELETED event: found at 10/02/2026, 01:00:00", out)
        self.assertIn("CAUTION", out)
        self.assertIn("could be on a phone now", out)

    def test_deleted_alone_has_no_caution(self):
        self.route([self.row("AVAILABLE"), self.row("DELETE", t="2026-10-02T01:00:00")])
        _, out, _ = self.run_cli("profile", "log", ICCID)
        self.assertIn("DELETED event: found at 2026-10-02T01:00:00", out)
        self.assertNotIn("CAUTION", out)
        self.assertNotIn("later", out)

    def test_reissue_after_deleted_is_not_called_off_phone(self):
        rows = [self.row("ENABLED", t="2026-10-01T01:00:00"), self.row("DELETED", t="2026-10-02T01:00:00"),
                self.row("CANCELED", t="2026-10-03T01:00:00"), self.row("AVAILABLE", t="2026-10-03T02:00:00"),
                self.row("INSTALLED", t="2026-10-04T01:00:00"), self.row("ENABLED", t="2026-10-04T02:00:00")]
        self.route(rows)
        _, out, _ = self.run_cli("profile", "log", ICCID)
        self.assertIn("later or simultaneous events (CANCELED, ENABLED, INSTALLED)", out)
        self.assertIn("could be on a phone now", out)
        self.assertIn("Not an off-phone conclusion", out)

    def test_iso_times_with_only_earlier_events_keep_the_plain_verdict(self):
        self.route([self.row("ENABLED", t="2026-10-01T01:00:00"), self.row("DELETED", t="2026-10-02T01:00:00"),
                    self.row("AVAILABLE", t="2026-10-02T01:00:01")])
        _, out, _ = self.run_cli("profile", "log", ICCID)
        self.assertIn("DELETED event: found at", out)
        self.assertNotIn("later or simultaneous", out)
        self.assertNotIn("CAUTION", out)

    def test_deleted_with_reason_is_a_failed_attempt_not_a_deletion(self):
        self.route([self.row("DELETE", reason="device busy")])
        _, out, _ = self.run_cli("profile", "log", ICCID)
        self.assertIn("DELETED event: not found", out)
        self.assertIn("device busy", out)

    def test_incomplete_log_is_flagged(self):
        self.route([self.row("AVAILABLE")], total=5)
        _, out, _ = self.run_cli("profile", "log", ICCID)
        self.assertIn("incomplete", out)
        self.assertIn("1 entries shown of 5", out)

    def test_json_masks_eid(self):
        self.route([self.row("AVAILABLE")])
        _, out, _ = self.run_cli("profile", "log", ICCID, "--json")
        self.assertNotIn(EID, out)

    def test_reason_text_is_scrubbed(self):
        self.route([self.row("ERROR", reason=f"failed for eid {EID} code {AC}")])
        _, out, _ = self.run_cli("profile", "log", ICCID)
        self.assertNotIn(EID, out)
        self.assertNotIn(AC, out)


class BatchResultTests(CliTestCase):
    def test_table_keys(self):
        self.server.routes["/api/v1/batch/info"] = lambda r: ok({
            "batchTaskInfo": {"batchCode": "B2026", "taskType": "GENERATE AC", "status": "COMPLETE", "total": 2,
                              "succeedNum": 1, "failedNum": 1, "createTime": "2026/10/01 10:00:00"},
            "results": [{"success": True, "iccid": ICCID, "eid": EID, "activationCode": AC, "acLink": AC_LINK},
                        {"success": False, "errorReason": "ICCID ALREADY EXISTS", "iccid": "8999000000000000002"}]})
        code, out, err = self.run_cli("batch", "result", "B2026")
        self.assertEqual(code, 0, err)
        self.assertIn("COMPLETE", out)
        self.assertIn("ICCID ALREADY EXISTS", out)
        self.assertNotIn(AC, out)
        self.assertNotIn(EID, out)
        self.assertEqual(self.server.requests[0].body, '{"batchCode":"B2026"}')
        self.assertAllSigned()

    def test_alternative_key_spellings_from_the_docs_example(self):
        self.server.routes["/api/v1/batch/info"] = lambda r: ok({
            "batchTaskInfo": {"batchCode": "B1", "status": "PROCESSING", "total": 1, "succeed": 0, "failed": 1},
            "result": [{"success": "false", "errorReson": "bad ki", "iccid": ICCID}]})
        code, out, _ = self.run_cli("batch", "result", "B1")
        self.assertEqual(code, 0)
        self.assertIn("bad ki", out)

    def test_missing_task_info_prints_what_is_there(self):
        self.server.routes["/api/v1/batch/info"] = lambda r: ok(
            {"results": [{"success": True, "iccid": ICCID, "eid": EID}]})
        code, out, err = self.run_cli("batch", "result", "B1")
        self.assertEqual(code, 0, err)
        self.assertIn(ICCID, out)
        self.assertIn("no batch task info", out)
        self.server.routes["/api/v1/batch/info"] = lambda r: ok({})
        code, out, err = self.run_cli("batch", "result", "B1")
        self.assertEqual(code, 0, err)
        self.assertIn("no batch task info", out)

    def test_wrong_type_task_info_still_fails_clearly(self):
        self.server.routes["/api/v1/batch/info"] = lambda r: ok({"batchTaskInfo": "oops", "results": []})
        code, _, err = self.run_cli("batch", "result", "B1")
        self.assertEqual(code, 1)
        self.assertIn("batchTaskInfo", err)

    def test_bad_batch_id_is_usage_error(self):
        self.assertEqual(self.run_cli("batch", "result", "../x")[0], 2)
        self.assertEqual(self.server.requests, [])
