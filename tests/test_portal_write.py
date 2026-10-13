"""The state-changing portal commands against the local mock portal: exact bodies and methods, dry run by
default, --yes, --force refusals with the website's warning, no retries, exit 3 on an unknown outcome, no token in output."""

import email.parser
import json
import os
import time
import unittest
from datetime import datetime, timedelta

import support
from support import EID, envelope
from simlessly_cli import portal
from test_portal import EXPIRED_MESSAGE, POSIX, TOKEN, bad_session
from test_portal_read import ICCID, ReadCase, prow

WARN_DELETE = ("Deleting profiles does not mean they are removed from the devices. "
               "Are you sure you want to proceed with the deletion?")
ON_PHONE = ["DOWNLOADED", "INSTALLED", "ENABLED", "DISABLED", "ENABLE", "DISABLE"]
WRITE_ARGV = {
    "notes": ["notes", ICCID, "hello"], "group-assign": ["group-assign", ICCID, "--group", "pilot"],
    "group-create": ["group-create", "newgroup"], "regenerate": ["regenerate", ICCID],
    "recycle": ["recycle", ICCID, "--at", "2099/01/02 14"], "delete": ["delete", ICCID],
}


def future(hours=48):
    return (datetime.now() + timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)


class WriteCase(ReadCase):
    """A portal with one profile (id 4242), a recycle state, a group list and recording write routes."""

    def setUp(self):
        super().setUp()
        self.status = "AVAILABLE"
        self.awaiting = False
        self.profile_extra = {}
        self.recycle_rows = None            # None: one row for ICCID from self.awaiting; else the rows to serve
        self.plan_type, self.ac_count = "PRO", 5
        self.writes = {}
        self.route("/api/v1/fleet/list", lambda rec: {"pageData": [prow(status=self.status, **self.profile_extra)],
                                                        "pageParam": {"total": 1}})
        self.route("/api/v1/fleet/recycle/query", lambda rec: self.recycle_rows if self.recycle_rows is not None else
                   [{"iccid": ICCID, "status": "AWAITING" if self.awaiting else "RECYCLED"}])
        self.route("/api/v1/plan/queryOrder", lambda rec: {"planType": self.plan_type, "status": "ACTIVE"})
        self.route("/api/v1/analytic/ac-count", lambda rec: {"acCount": self.ac_count})
        self.route("/api/v1/group/list", [{"id": 3, "name": "pilot", "count": 1, "note": ""},
                                          {"id": 4, "name": "Spare", "count": 0, "note": ""}])
        for path in portal.WRITE_PATHS:
            self.writes[path] = self.route(path, None)

    def written(self):
        """Every state-changing request the server received."""
        return [r for r in self.server.requests if r.path in portal.WRITE_PATHS]

    def assertNothingWritten(self):
        self.assertEqual(self.written(), [])

    def only_write(self, path):
        self.assertEqual([r.path for r in self.written()], [path])
        rec = self.written()[0]
        self.assertEqual((rec.method, rec.headers["Simlessly-Token"], rec.problems), ("POST", TOKEN, []))
        return rec


# ------------------------------------------------------------------ the gate

class GateTests(WriteCase):
    def test_every_write_command_is_a_dry_run_without_yes(self):
        self.awaiting = True
        self.status = "DOWNLOADED"
        for name, argv in WRITE_ARGV.items():
            self.server.requests.clear()
            code, out, err = self.run_cli("portal", *argv, *(["--force"] if name in ("regenerate", "recycle", "delete") else []))
            self.assertEqual(code, 2, (name, err))
            self.assertIn("Would send (dry run", out)
            self.assertIn("dry run: nothing was changed", err)
            self.assertClean(out, err)
            self.assertNothingWritten()
            for rec in self.server.requests:                           # the preview only reads
                self.assertIn(rec.path, portal.READ_PATHS)

    def test_yes_is_needed_exactly_and_abbreviations_are_refused(self):
        code, out, err = self.run_cli("portal", "notes", ICCID, "x", "--y")
        self.assertEqual(code, 2)
        self.assertIn("unrecognized", err)
        self.assertEqual(self.server.requests, [])

    def test_no_batch_operations(self):
        for argv in (["delete", ICCID, "8999000000000000002"], ["regenerate", ICCID, "8999000000000000002"],
                     ["notes", ICCID, "a", "b"], ["recycle", ICCID, "8999000000000000002", "--at", "2099/01/02 14"],
                     ["group-assign", ICCID, "8999000000000000002", "--group", "pilot"]):
            code, out, err = self.run_cli("portal", *argv, "--yes")
            self.assertEqual(code, 2, argv)
        for argv in (["delete", f"{ICCID},8999000000000000002"], ["regenerate", "all"]):
            code, out, err = self.run_cli("portal", *argv, "--yes")
            self.assertEqual(code, 2, argv)
        self.assertEqual(self.server.requests, [])

    def test_json_dry_run(self):
        code, out, err = self.run_cli("portal", "notes", ICCID, "hello", "--json")
        data = json.loads(out)
        self.assertEqual(code, 2)
        self.assertEqual(data["dry_run"], True)
        self.assertEqual(data["method"], "POST")
        self.assertEqual(data["url"], self.server.url + "/api/v1/fleet/update-notes")
        self.assertEqual(data["body"], {"ids": [4242], "notes": "hello"})
        self.assertEqual(data["profile"]["iccid"], ICCID)
        self.assertNotIn(TOKEN, out)

    def test_a_write_without_a_stored_session_sends_nothing(self):
        os.remove(self.path)
        code, out, err = self.run_cli("portal", "group-create", "x", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("simlessly portal login", err)
        self.assertEqual(self.server.requests, [])
        code, out, err = self.run_cli("portal", "group-create", "x")           # a dry run needs no session at all
        self.assertEqual(code, 2)
        self.assertEqual(self.server.requests, [])

    def test_portal_mutate_refuses_a_read_path(self):
        from simlessly_cli import portal_write
        from simlessly_cli.client import SimlesslyError
        with self.assertRaises(SimlesslyError):
            portal_write.portal_mutate(None, path="/api/v1/fleet/list", effect="x", cost="y", body={}, check_hint="z")


# ------------------------------------------------------------------ outcome handling

class OutcomeTests(WriteCase):
    def send(self):
        return self.run_cli("portal", "notes", ICCID, "hello", "--yes", "--timeout", "0.3")

    def test_success_is_exit_0_with_the_exact_post(self):
        code, out, err = self.run_cli("portal", "notes", ICCID, "ward 8", "--yes")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("updated", out)
        rec = self.only_write("/api/v1/fleet/update-notes")
        self.assertEqual(rec.body, '{"ids":[4242],"notes":"ward 8"}')
        self.assertEqual(rec.headers["Content-Type"], "application/json")
        self.assertClean(out, err)
        code, out, err = self.run_cli("portal", "notes", ICCID, "ward 9", "--yes", "--json")
        self.assertEqual(json.loads(out), {"success": True})

    def test_unknown_outcomes_are_exit_3_and_never_retried(self):
        cases = {
            "5xx": lambda rec: (503, b"down", {}),
            "unreadable": lambda rec: (200, b"<html>oops</html>", {}),
            "no envelope": lambda rec: (200, b'{"hello":1}', {}),
            "redirect": lambda rec: (302, b"", {"Location": "https://evil.example.com/"}),
            "oversize": lambda rec: (200, b"x" * ((1 << 20) + 5), {}),
            "timeout": lambda rec: (200, envelope(None), {}, 2.0),
        }
        for name, handler in cases.items():
            self.server.requests.clear()
            self.server.routes["/api/v1/fleet/update-notes"] = handler
            code, out, err = self.send()
            self.assertEqual(code, 3, (name, err))
            self.assertIn("OUTCOME UNKNOWN", err)
            self.assertIn("simlessly portal profile " + ICCID, err)
            self.assertNotIn("simlessly profile show", err)
            self.assertIn("Nothing was retried", err)
            self.assertEqual(len(self.written()), 1, name)                # exactly one attempt
            self.assertClean(out, err)

    def test_dropped_connection_is_exit_3(self):
        import socket
        import threading
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        hits = []

        def accept():
            conn, _ = sock.accept()
            hits.append(conn.recv(65536))
            conn.close()
        threading.Thread(target=accept, daemon=True).start()
        self.addCleanup(sock.close)
        self.route("/api/v1/fleet/list", {"pageData": [prow()]})
        # the lookup goes to the mock; the write goes to the dropper
        env = {**self.env}
        from simlessly_cli import portal_write
        original = portal_write.portal.build_portal_url
        portal_write.portal.build_portal_url = lambda base, path: (f"http://127.0.0.1:{port}" + path) if path in portal.WRITE_PATHS else original(base, path)
        self.addCleanup(setattr, portal_write.portal, "build_portal_url", original)
        from simlessly_cli import portal_cli
        real_client = portal_cli._client

        def client(ctx, token):
            c = real_client(ctx, token)
            return type("W", (), {"read": c.read, "write": lambda s, p, d=None: portal.PortalClient(f"http://127.0.0.1:{port}", token).write(p, d)})()
        portal_write._client = client
        self.addCleanup(setattr, portal_write, "_client", real_client)
        code, out, err = self.run_cli("portal", "notes", ICCID, "hello", "--yes", env=env)
        self.assertEqual(code, 3, err)
        self.assertIn("OUTCOME UNKNOWN", err)
        self.assertEqual(len(hits), 1)

    def test_a_refusal_from_the_portal_is_exit_1_not_3(self):
        self.server.routes["/api/v1/fleet/update-notes"] = lambda rec: (
            200, envelope(None, False, f"nope {TOKEN} {EID}", "50000"), {})
        code, out, err = self.send()
        self.assertEqual(code, 1)
        self.assertNotIn("OUTCOME UNKNOWN", err)
        self.assertIn("refused", err)
        self.assertClean(out, err)
        self.assertNotIn(EID, err)

    def test_session_expiry_on_a_write_is_exit_1(self):
        self.server.routes["/api/v1/fleet/update-notes"] = bad_session("10102")
        code, out, err = self.send()
        self.assertEqual((code, err), (1, "error: " + EXPIRED_MESSAGE + "\n"))
        self.assertEqual(len(self.written()), 1)

    def test_wrong_method_answer_is_exit_1_with_the_factual_message(self):
        self.server.routes["/api/v1/fleet/update-notes"] = lambda rec: (
            200, envelope(None, False, "request method not support[Request method 'POST' not supported]", "10008"), {})
        code, out, err = self.send()
        self.assertEqual(code, 1)
        self.assertIn("/api/v1/fleet/update-notes", err)
        self.assertIn("10008", err)
        self.assertIn("may have changed", err)
        self.assertNotIn("nofficial", err)

    def test_debug_never_shows_the_token(self):
        code, out, err = self.run_cli("portal", "notes", ICCID, "hello", "--yes", "--debug")
        self.assertEqual(code, 0)
        self.assertIn("> POST " + self.server.url + "/api/v1/fleet/update-notes", err)
        self.assertIn("> Simlessly-Token: [redacted]", err)
        self.assertClean(out, err)


# ------------------------------------------------------------------ notes / groups

class MetadataTests(WriteCase):
    def test_notes_validation_makes_no_call(self):
        for argv in (["notes", ICCID], ["notes", ICCID, "a", "--clear"], ["notes", ICCID, "x" * 101],
                     ["notes", ICCID, "bad\x07note"], ["notes", "123", "x"]):
            code, out, err = self.run_cli("portal", *argv, "--yes")
            self.assertEqual(code, 2, argv)
        self.assertEqual(self.server.requests, [])

    def test_notes_clear_and_the_current_note_is_shown(self):
        code, out, err = self.run_cli("portal", "notes", ICCID, "--clear")
        self.assertEqual(code, 2)
        self.assertIn('{"ids":[4242],"notes":""}', out)
        self.assertIn("current note: 'ward 7'", out)
        self.assertIn("no charge", out)
        code, out, err = self.run_cli("portal", "notes", ICCID, "--clear", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(self.only_write("/api/v1/fleet/update-notes").body, '{"ids":[4242],"notes":""}')

    def test_notes_on_demo_or_missing_profiles_are_refused(self):
        self.profile_extra = {"createBy": "demo"}
        code, out, err = self.run_cli("portal", "notes", ICCID, "x", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("demo", err)
        self.profile_extra = {"id": None}
        code, out, err = self.run_cli("portal", "notes", ICCID, "x", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("no profile id", err)
        self.route("/api/v1/fleet/list", {"pageData": []})
        code, out, err = self.run_cli("portal", "notes", ICCID, "x", "--yes")
        self.assertEqual(code, 1)
        self.assertNothingWritten()

    def test_group_assign_by_name_or_id(self):
        code, out, err = self.run_cli("portal", "group-assign", ICCID, "--group", "PILOT", "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.only_write("/api/v1/group/batchGroup").body, '{"groupId":3,"profileIds":[4242]}')
        self.server.requests.clear()
        code, out, err = self.run_cli("portal", "group-assign", ICCID, "--group", "4", "--yes")
        self.assertEqual(self.only_write("/api/v1/group/batchGroup").body, '{"groupId":4,"profileIds":[4242]}')
        self.assertIn("'Spare'", out)

    def test_group_assign_unknown_group_is_usage(self):
        code, out, err = self.run_cli("portal", "group-assign", ICCID, "--group", "nope", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("pilot", err)
        self.assertNothingWritten()

    def test_group_assign_dry_run_shows_the_effect(self):
        code, out, err = self.run_cli("portal", "group-assign", ICCID, "--group", "pilot")
        self.assertEqual(code, 2)
        self.assertIn("metadata only", out)
        self.assertIn("profile  ", out)

    def test_group_create(self):
        code, out, err = self.run_cli("portal", "group-create", "Wave 2", "--note", "second wave", "--yes")
        self.assertEqual(code, 0, err)
        rec = self.only_write("/api/v1/group/add")
        self.assertEqual(rec.body, '{"name":"Wave 2","note":"second wave"}')
        self.server.requests.clear()
        self.run_cli("portal", "group-create", "Bare", "--yes")
        self.assertEqual(self.only_write("/api/v1/group/add").body, '{"name":"Bare","note":""}')
        for argv in (["group-create", ""], ["group-create", "x" * 101], ["group-create", "a", "--note", "n" * 201]):
            self.assertEqual(self.run_cli("portal", *argv, "--yes")[0], 2, argv)


# ------------------------------------------------------------------ the on-phone guard

class GuardTests(WriteCase):
    COMMANDS = {
        "delete": (["delete", ICCID], "/api/v1/fleet/delete"),
        "regenerate": (["regenerate", ICCID], "/api/v1/fleet/re-generate"),
        "recycle": (["recycle", ICCID, "--at", "2099/01/02 14"], "/api/v1/fleet/recycle"),
    }

    def setUp(self):
        super().setUp()
        self.awaiting = True          # the recycle command needs it; the others see it as one more reason

    def test_refused_when_the_status_means_on_a_phone(self):
        self.awaiting = False
        for status in ON_PHONE + ["downloaded", " Enabled "]:
            self.status = status
            for name in ("delete", "regenerate"):
                argv, path = self.COMMANDS[name]
                self.server.requests.clear()
                code, out, err = self.run_cli("portal", *argv, "--yes")
                self.assertEqual(code, 1, (name, status))
                self.assertIn("refusing to", err)
                self.assertIn("on, or possibly on, a phone", err)
                self.assertIn("--force", err)
                self.assertIn("Nothing was sent", err)
                self.assertNothingWritten()
                self.assertClean(out, err)
        self.status = "ENABLED"
        code, out, err = self.run_cli("portal", "delete", ICCID, "--yes")
        self.assertIn(WARN_DELETE, err)                                   # the website's own warning
        code, out, err = self.run_cli("portal", "regenerate", ICCID, "--yes")
        self.assertIn("may significantly impact the previous profile's functionality", err)

    def test_the_refusal_happens_in_a_dry_run_too(self):
        self.status = "INSTALLED"
        code, out, err = self.run_cli("portal", "delete", ICCID)
        self.assertEqual(code, 1)
        self.assertNotIn("Would send", out)

    def test_an_awaiting_recycle_state_refuses_even_for_an_available_profile(self):
        self.status = "AVAILABLE"
        for name in ("delete", "regenerate"):
            code, out, err = self.run_cli("portal", *self.COMMANDS[name][0], "--yes")
            self.assertEqual(code, 1, name)
            self.assertIn("recycle state is AWAITING", err)
        self.assertNothingWritten()

    def test_unknown_or_missing_status_is_refused(self):
        self.awaiting = False
        self.status = ""
        code, out, err = self.run_cli("portal", "delete", ICCID, "--yes")
        self.assertEqual(code, 1)
        self.assertIn("no status", err)

    def test_force_shows_the_warning_and_then_sends(self):
        self.status = "ENABLED"
        for name, (argv, path) in self.COMMANDS.items():
            if name == "recycle":
                continue                      # an on-phone profile in AWAITING is the one valid recycle case: no --force needed
            self.server.requests.clear()
            code, out, err = self.run_cli("portal", *argv, "--force")
            self.assertEqual(code, 2, (name, err))
            self.assertIn("FORCED (--force)", out)
            self.assertIn("The website warns:", out)
            self.assertNothingWritten()
            code, out, err = self.run_cli("portal", *argv, "--force", "--yes")
            self.assertEqual(code, 0, (name, err))
            self.only_write(path)

    def test_force_does_not_override_demo_data(self):
        self.profile_extra = {"createBy": "demo"}
        for name, (argv, path) in self.COMMANDS.items():
            code, out, err = self.run_cli("portal", *argv, "--force", "--yes")
            self.assertEqual(code, 1, name)
            self.assertIn("demo", err)
        self.assertNothingWritten()

    def test_force_without_yes_never_sends(self):
        self.status = "DOWNLOADED"
        self.run_cli("portal", "delete", ICCID, "--force")
        self.assertNothingWritten()

    def test_available_and_similar_statuses_carry_the_not_proof_caveat(self):
        self.awaiting = False
        for status in ("AVAILABLE", "EXPIRED", "CANCELED", "REMOVED"):
            self.status = status
            code, out, err = self.run_cli("portal", "delete", ICCID)
            self.assertEqual(code, 2, status)
            self.assertIn("not proof the eSIM left the phone", out)
        for status in ("AVAILABLE", "DELETED", "ERROR"):          # regenerate: the off-phone ones pass
            self.status = status
            self.assertEqual(self.run_cli("portal", "regenerate", ICCID)[0], 2, status)

    def test_the_precheck_reads_the_recycle_state_with_the_iccid_list(self):
        self.awaiting = False
        self.status = "ERROR"
        self.run_cli("portal", "delete", ICCID, "--yes")
        paths = [r.path for r in self.server.requests]
        self.assertEqual(paths, ["/api/v1/fleet/list", "/api/v1/fleet/recycle/query", "/api/v1/fleet/delete"])
        self.assertEqual(self.server.requests[1].body, '{"iccid":["%s"]}' % ICCID)


class AllowlistGuardTests(WriteCase):
    """The guard is an allowlist: only known off-phone statuses and known non-AWAITING recycle rows pass."""

    def test_campaign_and_preoccupied_profiles_are_never_deleted_or_regenerated(self):
        for extra in ({"campaignFlag": True}, {"preOccupy": True}, {"campaignFlag": 1}, {"preOccupy": "true"}):
            self.profile_extra = extra
            for name in ("delete", "regenerate"):
                for flags in ((), ("--force",)):
                    code, out, err = self.run_cli("portal", name, ICCID, *flags, "--yes")
                    self.assertEqual(code, 1, (extra, name, flags))
                    self.assertIn("website does not offer this action", err)
                    self.assertIn("even with --force", err)
        self.assertNothingWritten()
        self.profile_extra = {"campaignFlag": False, "preOccupy": "false"}          # explicit false values pass
        self.assertEqual(self.run_cli("portal", "delete", ICCID, "--yes")[0], 0)

    def test_unrecognised_fleet_statuses_are_refused_without_force(self):
        for status in ("INSTALLING", "DOWNLOADING", "RELEASED", "SOMETHING_NEW", "AUTHENTICATED", "LOCKED"):
            self.status = status
            for name in ("delete", "regenerate"):
                code, out, err = self.run_cli("portal", name, ICCID, "--yes")
                self.assertEqual(code, 1, (name, status))
                self.assertIn("unrecognised status", err)
                self.assertNotIn("The website warns", err)             # the website has no text for this
        self.assertNothingWritten()
        self.status = "SOMETHING_NEW"
        code, out, err = self.run_cli("portal", "delete", ICCID, "--force", "--yes")
        self.assertEqual(code, 0, err)
        self.only_write("/api/v1/fleet/delete")

    def test_unknown_recycle_states_are_refused_and_zero_means_awaiting(self):
        for rows, text in (([{"iccid": ICCID, "status": "PENDING"}], "not a recognised one"),
                           ([{"iccid": ICCID, "status": None}], "not a recognised one"),
                           ([{"iccid": ICCID, "status": 0}], "AWAITING"), ([{"iccid": ICCID, "status": "0"}], "AWAITING"),
                           ([{"iccid": ICCID, "status": 7}], "not a recognised one"), ([], "no row for this ICCID"),
                           ([{"iccid": ICCID, "status": "RECYCLED"}, {"iccid": ICCID, "status": "RECYCLED"}], "2 rows")):
            self.recycle_rows = rows
            for name in ("delete", "regenerate"):
                code, out, err = self.run_cli("portal", name, ICCID, "--yes")
                self.assertEqual(code, 1, (name, rows))
                self.assertIn(text, err)
        self.assertNothingWritten()
        for status in ("RECYCLED", "INVALID", "recycled"):                     # known and clear: passes
            self.recycle_rows = [{"iccid": ICCID, "status": status}]
            self.assertEqual(self.run_cli("portal", "delete", ICCID)[0], 2, status)

    def test_only_this_iccids_recycle_row_counts(self):
        other = "8999000000000000002"
        self.recycle_rows = [{"iccid": other, "status": "AWAITING"}, {"iccid": ICCID, "status": "RECYCLED"}]
        self.assertEqual(self.run_cli("portal", "delete", ICCID)[0], 2)           # the other profile's AWAITING is ignored
        self.status = "ENABLED"
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--force", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("AWAITING", err)
        self.assertNothingWritten()
        self.recycle_rows = [{"iccid": other, "status": "AWAITING"}]               # no row for this ICCID: fails closed
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--force", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("no row for this ICCID", err)
        self.recycle_rows = [{"iccid": ICCID, "status": "AWAITING"}, {"iccid": ICCID, "status": "AWAITING"}]
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--force", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("2 rows", err)
        self.assertNothingWritten()
        self.recycle_rows = [{"iccid": other, "status": "RECYCLED"}, {"iccid": ICCID.lower(), "status": 0}]
        self.assertEqual(self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--yes")[0], 0)

    def test_regenerate_needs_force_for_platform_bookkeeping_statuses(self):
        for status in ("EXPIRED", "CANCELED", "REMOVED", "cancelled"):
            self.status = status
            code, out, err = self.run_cli("portal", "regenerate", ICCID, "--yes")
            self.assertEqual(code, 1, status)
            self.assertIn("platform bookkeeping", err)
            self.assertIn("not proof the eSIM left the phone", err)
            self.assertNotIn("The website warns", err)
        self.assertNothingWritten()
        self.status = "EXPIRED"
        code, out, err = self.run_cli("portal", "regenerate", ICCID, "--force", "--yes")
        self.assertEqual(code, 0, err)
        self.only_write("/api/v1/fleet/re-generate")
        self.server.requests.clear()
        self.assertEqual(self.run_cli("portal", "delete", ICCID, "--yes")[0], 0)      # delete leaves the phone alone

    def test_recycle_with_an_unrecognised_or_missing_status_needs_force(self):
        self.awaiting = True
        for status in ("WHATEVER", ""):
            self.status = status
            code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--yes")
            self.assertEqual(code, 1, status)
            self.assertNotIn("The website warns", err)
        self.assertNothingWritten()
        self.status = "WHATEVER"
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--force", "--yes")
        self.assertEqual(code, 0, err)
        self.only_write("/api/v1/fleet/recycle")


# ------------------------------------------------------------------ delete / regenerate / recycle bodies

class ActionTests(WriteCase):
    def test_delete_body_and_text(self):
        code, out, err = self.run_cli("portal", "delete", ICCID)
        self.assertEqual(code, 2)
        self.assertIn('{"ids":[4242]}', out)
        self.assertIn("irreversible", out)
        self.assertIn("not removed from any device", out)
        code, out, err = self.run_cli("portal", "delete", ICCID, "--yes")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.only_write("/api/v1/fleet/delete").body, '{"ids":[4242]}')

    def test_regenerate_body_billing_and_async_pointer(self):
        code, out, err = self.run_cli("portal", "regenerate", ICCID)
        self.assertEqual(code, 2)
        self.assertIn("BILLABLE", out)
        self.assertIn("batch-logs --type RE_GENERATE", out)
        code, out, err = self.run_cli("portal", "regenerate", ICCID, "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.only_write("/api/v1/fleet/re-generate").body,
                         '{"configId":"77","profileIds":[4242],"acFormat":["STRING"]}')
        self.assertIn("batch-logs", out)
        self.server.requests.clear()
        self.run_cli("portal", "regenerate", ICCID, "--picture", "--expire-time", "2099-01-02 03:04:05", "--yes")
        self.assertEqual(self.only_write("/api/v1/fleet/re-generate").body,
                         '{"configId":"77","profileIds":[4242],"acFormat":["STRING","PICTURE"],"expireTime":"2099/01/02 03:04:05"}')

    def test_regenerate_bad_input_and_missing_config(self):
        for argv in (["--expire-time", "tomorrow"], ["--expire-time", "2099/13/40 00:00:00"]):
            self.assertEqual(self.run_cli("portal", "regenerate", ICCID, *argv, "--yes")[0], 2)
        self.assertEqual(self.server.requests, [])
        self.profile_extra = {"configId": None}
        code, out, err = self.run_cli("portal", "regenerate", ICCID, "--yes")
        self.assertEqual(code, 1)
        self.assertIn("no configId", err)
        self.assertNothingWritten()

    def test_recycle_body_and_preconditions(self):
        self.awaiting = True
        self.status = "ENABLED"
        at = future().strftime("%Y/%m/%d %H")
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", at)
        self.assertEqual(code, 2)                                          # the valid case needs no --force
        self.assertIn("remove the profile from the phone", out)
        self.assertIn("Only the 'Other time' form is supported", out)
        self.assertNotIn("FORCED", out)
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", at, "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.only_write("/api/v1/fleet/recycle").body,
                         '{"iccid":"%s","recycleTime":"%s:00:00"}' % (ICCID, at))

    def test_recycle_time_formats_and_limits(self):
        self.awaiting, self.status = True, "ENABLED"
        stamp = future()
        for given in (stamp.strftime("%Y-%m-%d %H"), stamp.strftime("%Y-%m-%dT%H:00:00"), stamp.strftime("%Y/%m/%d %H:00")):
            self.server.requests.clear()
            self.run_cli("portal", "recycle", ICCID, "--at", given, "--force", "--yes")
            self.assertEqual(json.loads(self.only_write("/api/v1/fleet/recycle").body)["recycleTime"],
                             stamp.strftime("%Y/%m/%d %H:00:00"))
        self.server.requests.clear()
        for bad in ("now", "2099/01/02", "2099/01/02 14:30", "2099/02/31 10", "2001/01/01 00", ""):
            code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", bad, "--force", "--yes")
            self.assertEqual(code, 2, bad)
        self.assertEqual(self.server.requests, [])
        self.assertEqual(self.run_cli("portal", "recycle", ICCID, "--now", "--yes")[0], 2)      # 'Now' is not implemented

    def test_recycle_needs_an_awaiting_state_and_a_profile_that_is_not_available(self):
        self.status, self.awaiting = "ENABLED", False
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--force", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("AWAITING", err)
        self.status, self.awaiting = "AVAILABLE", True
        code, out, err = self.run_cli("portal", "recycle", ICCID, "--at", "2099/01/02 14", "--force", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("AVAILABLE", err)
        self.assertNothingWritten()


# ------------------------------------------------------------------ generate-ac

class GenerateAcTests(WriteCase):
    def setUp(self):
        super().setUp()
        self.gpg = self.tmp / "records.gpg"
        self.gpg.write_bytes(b"-----BEGIN PGP MESSAGE-----\nSECRETPAYLOAD-KI-OPC\n-----END PGP MESSAGE-----\n")
        self.xlsx = self.tmp / "records.xlsx"
        self.xlsx.write_bytes(b"PK\x03\x04plain-sheet")

    def argv(self, *extra, file=None, kind="pgp", config="77"):
        return ["generate-ac", "--config", config, "--file", str(file or self.gpg), "--upload-type", kind, *extra]

    @staticmethod
    def parts(rec):
        msg = email.parser.BytesParser().parsebytes(b"Content-Type: " + rec.headers["Content-Type"].encode() + b"\r\n\r\n" + rec.raw)
        return [(p.get_param("name", header="content-disposition"), p.get_filename(), p.get_payload(decode=True)) for p in msg.get_payload()]

    def test_dry_run_shows_fields_and_billing_but_never_the_content(self):
        code, out, err = self.run_cli("portal", *self.argv("--picture"))
        self.assertEqual(code, 2)
        for text in ("BILLABLE", "configId=77", "uploadType=1", "acFormats=STRING", "acFormats=PICTURE", "records.gpg",
                     "sha256", "content not shown", "batch-logs", "multipart/form-data"):
            self.assertIn(text, out)
        self.assertNotIn("SECRETPAYLOAD", out + err)
        self.assertNothingWritten()
        code, out, err = self.run_cli("portal", *self.argv(), "--json")
        data = json.loads(out)
        self.assertEqual(data["body"]["file"]["name"], "records.gpg")
        self.assertNotIn("SECRETPAYLOAD", out)

    def test_yes_sends_the_exact_multipart(self):
        code, out, err = self.run_cli("portal", *self.argv("--picture", "--ac-link"), "--yes")
        self.assertEqual(code, 0, err)
        rec = self.only_write("/api/v1/fleet/generateAc")
        self.assertTrue(rec.headers["Content-Type"].startswith("multipart/form-data; boundary="))
        parts = self.parts(rec)
        self.assertEqual([(n, v) for n, f, v in parts if f is None],
                         [("configId", b"77"), ("uploadType", b"1"), ("acFormats", b"STRING"), ("acFormats", b"PICTURE"),
                          ("acFormats", b"AC_LINK")])
        files = [(n, f, v) for n, f, v in parts if f is not None]
        self.assertEqual(files, [("file", "records.gpg", self.gpg.read_bytes())])
        self.assertNotIn("SECRETPAYLOAD", out + err)
        self.assertIn("batch-logs", out)

    def test_plain_spreadsheet_warns_and_uses_upload_type_0(self):
        code, out, err = self.run_cli("portal", *self.argv(file=self.xlsx, kind="plain"))
        self.assertEqual(code, 2)
        self.assertIn("uploadType=0", out)
        self.assertIn("without the PGP layer", out)
        code, out, err = self.run_cli("portal", *self.argv(file=self.xlsx, kind="plain"), "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual([p for p in self.parts(self.written()[0]) if p[0] == "uploadType"][0][2], b"0")

    def test_config_name_is_looked_up_first(self):
        self.route("/api/v1/config/name/query", [{"configId": 77, "configName": "demo-config"}])
        code, out, err = self.run_cli("portal", *self.argv(config="demo-config"), "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.server.requests[0].path, "/api/v1/config/name/query")
        self.assertEqual(self.server.requests[0].query, "filterDemo=false")
        self.assertEqual([p for p in self.parts(self.written()[0]) if p[0] == "configId"][0][2], b"77")

    def test_bad_files_make_no_call(self):
        empty = self.tmp / "empty.gpg"
        empty.write_bytes(b"")
        big = self.tmp / "big.gpg"
        big.write_bytes(b"x" * ((8 << 20) + 1))
        (self.tmp / "dir.gpg").mkdir()
        cases = [self.argv(file=self.xlsx), self.argv(file=self.gpg, kind="plain"), self.argv(file=empty),
                 self.argv(file=big), self.argv(file=self.tmp / "missing.gpg"), self.argv(file=self.tmp / "dir.gpg"),
                 ["generate-ac", "--config", "77", "--file", str(self.gpg)]]
        if POSIX:
            link = self.tmp / "link.gpg"
            os.symlink(self.gpg, link)
            cases.append(self.argv(file=link))
        for argv in cases:
            code, out, err = self.run_cli("portal", *argv, "--yes")
            self.assertEqual(code, 2, argv)
        self.assertEqual(self.server.requests, [])

    def test_the_debug_log_shows_field_names_but_not_the_file(self):
        code, out, err = self.run_cli("portal", *self.argv(), "--yes", "--debug")
        self.assertEqual(code, 0)
        self.assertIn("[multipart: configId=77", err)
        self.assertNotIn("SECRETPAYLOAD", err)
        self.assertClean(out, err)

    def test_an_unknown_outcome_is_exit_3(self):
        self.server.routes["/api/v1/fleet/generateAc"] = lambda rec: (503, b"down", {})
        code, out, err = self.run_cli("portal", *self.argv(), "--yes")
        self.assertEqual(code, 3)
        self.assertIn("batch-logs", err)
        self.assertEqual(len(self.written()), 1)


    def test_default_plan_with_a_profile_is_refused_before_anything_is_sent(self):
        self.plan_type = "DEFAULT"
        for count in (1, 3):
            self.ac_count = count
            for yes in ((), ("--yes",)):
                code, out, err = self.run_cli("portal", *self.argv(), *yes)
                self.assertEqual(code, 1, (count, yes))
                self.assertIn("limited to 1 profile", err)
                self.assertIn(f"acCount={count}", err)
        self.assertNothingWritten()
        self.ac_count = "many"                                                         # unreadable count fails closed
        self.assertEqual(self.run_cli("portal", *self.argv(), "--yes")[0], 1)
        self.assertNothingWritten()

    def test_default_plan_with_no_profile_and_other_plans_go_ahead_and_show_both_values(self):
        self.plan_type, self.ac_count = "DEFAULT", 0
        code, out, err = self.run_cli("portal", *self.argv())
        self.assertEqual(code, 2)
        self.assertIn("planType='DEFAULT', acCount=0", out)
        self.assertEqual(self.run_cli("portal", *self.argv(), "--yes")[0], 0)
        self.server.requests.clear()
        self.plan_type, self.ac_count = "PRO", 500
        self.assertEqual(self.run_cli("portal", *self.argv(), "--yes")[0], 0)
        paths = [r.path for r in self.server.requests]
        self.assertEqual(paths, ["/api/v1/plan/queryOrder", "/api/v1/analytic/ac-count", "/api/v1/fleet/generateAc"])


if __name__ == "__main__":
    unittest.main()
