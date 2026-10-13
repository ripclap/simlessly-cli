"""tools/api_watch.py: snapshot extraction, diff and apply, offline against small fabricated pages and scripts."""

import contextlib
import copy
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import support  # noqa: F401  (network guard: any real request fails the test)
from support import MockPortal, envelope, ok

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import api_watch  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "api_watch"
ENDPOINTS_FILE = Path(__file__).resolve().parent.parent / "src" / "simlessly_cli" / "portal_endpoints.json"


def read(*parts):
    return FIXTURES.joinpath(*parts).read_text(encoding="utf-8")


class FakeSite:
    """Serves the fixture pages by URL and records every request."""

    def __init__(self, portal_edit=None):
        self.requests = []
        fallback = read("docs", "fallback.html")
        self.pages = {
            "https://docs.simlessly.com/": read("docs", "index.html"),
            "https://docs.simlessly.com/rsp/api-reference/overview.html": read("docs", "rsp_overview.html"),
            "https://docs.simlessly.com/rsp/api-reference/items/list-things.html": read("docs", "rsp_list_things.html"),
            "https://docs.simlessly.com/rsp/api-reference/items/add-thing.html": read("docs", "rsp_add_thing.html"),
            "https://docs.simlessly.com/rsp/api-reference/items/gone.html": fallback,          # HTTP 200, landing page
            "https://docs.simlessly.com/cmp/api-reference/token.html": read("docs", "cmp_token.html"),
            "https://rsp.simlessly.com/": read("portal", "index.html"),
        }
        for name in ("index-AAAAAAAA.js", "things-BBBBBBBB.js", "files-CCCCCCCC.js"):
            text = read("portal", name)
            self.pages["https://rsp.simlessly.com/assets/" + name] = portal_edit(name, text) if portal_edit else text

    def __call__(self, url):
        api_watch.check_url(url)
        self.requests.append(url)
        if url not in self.pages:
            raise api_watch.NotFound(url)
        return self.pages[url]


def small_limits():
    return mock.patch.multiple(api_watch, MIN_DOC_PAGES=3, MIN_DOC_ENDPOINTS=2, MIN_PORTAL_PATHS=5)


# ------------------------------------------------------------------ documentation

class DocsExtractionTests(unittest.TestCase):
    def setUp(self):
        self.site = FakeSite()
        with small_limits():
            self.docs = api_watch.collect_docs(self.site)

    def endpoint(self, page):
        endpoints = self.docs["pages"][page]["endpoints"]
        self.assertEqual(len(endpoints), 1, page)
        return endpoints[0]

    def test_method_heading_layout(self):
        e = self.endpoint("/rsp/api-reference/items/list-things.html")
        self.assertEqual((e["product"], e["title"], e["method"], e["url"]),
                         ("rsp", "List Things", "POST", "https://rsp.example.test/api/v1/things/list"))
        self.assertEqual(e["request"], [{"name": "nameFilter", "type": "String", "required": False},
                                        {"name": "pageParam", "type": "PageParam", "required": True}])
        self.assertEqual([f["name"] for f in e["response"]], ["pageParam", "things"])
        self.assertEqual(e["response"][1]["type"], "List< String>")
        self.assertEqual(e["response_types"], {"PageParam": [{"name": "pageNum", "type": "Integer", "required": True},
                                                            {"name": "pageSize", "type": "Integer", "required": True},
                                                            {"name": "total", "type": "Integer", "required": True}]})
        self.assertEqual(e["request_types"], {})

    def test_endpoint_line_layout_with_base_url_and_nested_type(self):
        e = self.endpoint("/rsp/api-reference/items/add-thing.html")
        self.assertEqual((e["method"], e["url"], e["title"]),
                         ("POST", "https://rsp.example.test/api/v1/open/things/add", "Add Thing"))
        self.assertEqual([(f["name"], f["required"]) for f in e["request"]],
                         [("color", False), ("parts", True), ("thingName", True)])
        self.assertEqual(list(e["request_types"]), ["Part Object Structure"])
        self.assertEqual(e["response"], [{"name": "thingId", "type": "String", "required": True}])

    def test_http_method_line_layout_and_request_headers(self):
        e = self.endpoint("/cmp/api-reference/token.html")
        self.assertEqual((e["product"], e["method"], e["url"]), ("cmp", "POST", "https://cmp.example.test/api/v1/external/token"))
        self.assertEqual([f["name"] for f in e["request_headers"]], ["clientId", "clientSecret"])
        self.assertEqual(e["request"], [])
        self.assertEqual([(f["name"], f["required"]) for f in e["response"]], [("expireIn", False), ("token", True)])

    def test_prose_page_has_no_endpoints_and_non_parameter_tables_are_ignored(self):
        self.assertEqual(self.docs["pages"]["/rsp/api-reference/overview.html"]["endpoints"], [])
        text = json.dumps(self.docs)
        self.assertNotIn("Colours", text)
        self.assertNotIn("opens new window", text)
        self.assertNotIn('"POST": 1', text)             # code blocks and scripts are not read

    def test_landing_page_answer_and_missing_page_are_listed_as_unavailable(self):
        self.assertEqual(self.docs["unavailable"], ["/rsp/api-reference/items/gone.html",
                                                    "/rsp/api-reference/items/overview.html"])
        self.assertNotIn("/rsp/api-reference/items/gone.html", self.docs["pages"])

    def test_only_documentation_hosts_are_requested_and_never_an_api_path(self):
        self.assertTrue(self.site.requests)
        for url in self.site.requests:
            self.assertTrue(url.startswith("https://docs.simlessly.com/"), url)
            self.assertNotIn("/api/", url)
        self.assertEqual(len(self.site.requests), len(set(self.site.requests)))

    def test_output_is_deterministic_and_sorted(self):
        with small_limits():
            again = api_watch.collect_docs(FakeSite())
        self.assertEqual(api_watch.dump_json(self.docs), api_watch.dump_json(again))
        names = [f["name"] for f in self.endpoint("/rsp/api-reference/items/list-things.html")["response"]]
        self.assertEqual(names, sorted(names))

    def test_an_unrecognized_site_fails_instead_of_writing_an_empty_snapshot(self):
        site = FakeSite()
        site.pages["https://docs.simlessly.com/"] = "<html><body><p>moved</p></body></html>"
        with small_limits(), self.assertRaisesRegex(api_watch.WatchError, "no API reference links"):
            api_watch.collect_docs(site)
        with self.assertRaisesRegex(api_watch.WatchError, "structure changed"):
            api_watch.collect_docs(FakeSite())          # default limits: far more pages and endpoints expected

    def test_a_failed_fetch_fails_the_run(self):
        site = FakeSite()

        def broken(url):
            if url.endswith("list-things.html"):
                raise api_watch.WatchError(url + ": HTTP 503")
            return site(url)
        with small_limits(), self.assertRaisesRegex(api_watch.WatchError, "HTTP 503"):
            api_watch.collect_docs(broken)


# ------------------------------------------------------------------ portal

class PortalScanTests(unittest.TestCase):
    EXPECTED = {
        "/api/v1/account/login": ("POST", "json", ["index"]),
        "/api/v1/account/logout": ("GET", "query", ["index"]),
        "/api/v1/files/list": ("GET", "query", ["files"]),
        "/api/v1/owner/info": ("GET", "query", ["index"]),
        "/api/v1/site/info": ("GET", "fetch", ["index"]),
        "/api/v1/things/delete": ("POST", "json", ["things"]),
        "/api/v1/things/detail": ("GET", "query", ["things"]),
        "/api/v1/things/export": ("POST", "json", ["things"]),
        "/api/v1/things/import": ("POST", "multipart", ["things"]),
        "/api/v1/things/key": ("GET", "navigation", ["things"]),
        "/api/v1/things/list": ("POST", "json", ["things"]),
        "/api/v1/things/{}/render/{}": ("POST", "json", ["things"]),
    }

    def scan(self, site=None):
        with small_limits():
            return api_watch.scan_portal(site or FakeSite())

    def test_every_path_gets_its_method_transport_and_page_module(self):
        result = self.scan()
        got = {p: (e["method"], e["transport"], e["modules"]) for p, e in result["endpoints"].items()}
        self.assertEqual(got, self.EXPECTED)
        self.assertEqual(list(result["endpoints"]), sorted(result["endpoints"]))

    def test_session_details(self):
        result = self.scan()
        self.assertEqual(result["session_headers"], ["Simlessly-Timestamp", "Simlessly-Token"])
        self.assertEqual(result["session_cookies"], ["simlessly_token"])
        self.assertEqual(result["session_invalid_codes"], ["20001", "20002"])

    def test_helpers_are_found_by_behaviour_not_by_name(self):
        renames = {"getq": "zz1", "postj": "zz2", "upload": "zz3", "send": "zz4"}

        def rename(name, text):
            for old, new in renames.items():
                text = text.replace(old, new)
            return text
        self.assertEqual(self.scan(FakeSite(rename))["endpoints"], self.scan()["endpoints"])
        helpers = api_watch.find_helpers(read("portal", "index-AAAAAAAA.js"))
        self.assertEqual({helpers[n] for n in ("getq", "postj", "upload")}, {"query", "json", "multipart"})
        self.assertNotIn("doLogin", helpers)             # a wrapper with a literal path is not a helper

    def test_a_call_moved_to_another_helper_changes_the_method(self):
        def move(name, text):
            return text.replace('return n("/api/v1/things/detail",e)', 'return t("/api/v1/things/detail",e)')
        result = self.scan(FakeSite(move))
        self.assertEqual(result["endpoints"]["/api/v1/things/detail"]["method"], "POST")
        self.assertEqual(result["endpoints"]["/api/v1/things/detail"]["transport"], "json")

    def test_a_helper_that_changes_behaviour_is_followed(self):
        def as_query(name, text):
            return text.replace('function postj(e,t,n={},r){return n.data=t||n.data', 'function postj(e,t,n={},r){return n.params=t||n.params')
        result = self.scan(FakeSite(as_query))
        self.assertEqual(result["endpoints"]["/api/v1/things/list"]["method"], "GET")
        self.assertEqual(result["endpoints"]["/api/v1/things/list"]["transport"], "query")

    def test_a_path_called_in_two_ways_is_a_conflict_and_an_unknown_caller_is_unresolved(self):
        def edit(name, text):
            if name.startswith("files"):
                text += 'import{p as pp}from"./index-AAAAAAAA.js";function again(e){return pp("/api/v1/files/list",e)}'
                text += 'function odd(e){return mystery("/api/v1/odd/thing",e)}'
            return text
        with mock.patch.object(api_watch, "MAX_UNCLASSIFIED_SHARE", 1.0):
            result = self.scan(FakeSite(edit))
        self.assertEqual(result["endpoints"]["/api/v1/files/list"]["method"], "CONFLICT")
        self.assertEqual(result["endpoints"]["/api/v1/odd/thing"]["method"], "UNKNOWN")

    def test_too_many_unclassified_paths_fail_the_scan(self):
        def edit(name, text):
            return text.replace('return postj("/api/v1/account/login",e)', 'return mystery("/api/v1/account/login",e)')
        with self.assertRaisesRegex(api_watch.WatchError, r"method of 1 of 12 /api/ paths could not be determined"):
            self.scan(FakeSite(edit))
        with mock.patch.object(api_watch, "MAX_UNCLASSIFIED_SHARE", 0.1):
            self.assertEqual(self.scan(FakeSite(edit))["endpoints"]["/api/v1/account/login"]["method"], "UNKNOWN")

    VENDOR = "var vendor=(function(){function postj(e,t){return e.params=t,e}return postj})();"

    def test_a_nested_function_that_reuses_a_helper_name_makes_it_ambiguous(self):
        index = read("portal", "index-AAAAAAAA.js")
        helpers = api_watch.find_helpers(index + self.VENDOR)
        self.assertEqual(helpers["postj"], "ambiguous")
        self.assertEqual((helpers["getq"], helpers["upload"]), ("query", "multipart"))
        # calls through the ambiguous name are not classified, so the scan fails instead of flipping methods
        with self.assertRaisesRegex(api_watch.WatchError, "could not be determined"):
            self.scan(FakeSite(lambda n, t: t + self.VENDOR if n.startswith("index") else t))
        with mock.patch.object(api_watch, "MAX_UNCLASSIFIED_SHARE", 1.0):
            result = self.scan(FakeSite(lambda n, t: t + self.VENDOR if n.startswith("index") else t))
        for path in ("/api/v1/account/login", "/api/v1/things/list", "/api/v1/things/delete"):
            self.assertEqual(result["endpoints"][path]["method"], "UNKNOWN", path)

    def test_a_second_definition_of_the_same_kind_is_not_ambiguous(self):
        again = "var vendor=(function(){function postj(e,t){return e.data=t,e}return postj})();"
        self.assertEqual(api_watch.find_helpers(read("portal", "index-AAAAAAAA.js") + again)["postj"], "json")
        self.assertEqual(self.scan(FakeSite(lambda n, t: t + again if n.startswith("index") else t))["endpoints"],
                         self.scan()["endpoints"])

    def test_an_imported_helper_that_clashes_with_a_local_one_is_ambiguous(self):
        def edit(name, text):
            if name.startswith("things"):
                return text + "function t(e,r){return e.params=r,e}"          # local 't' is a query helper, imported 't' is json
            return text
        with mock.patch.object(api_watch, "MAX_UNCLASSIFIED_SHARE", 1.0):
            result = self.scan(FakeSite(edit))
        self.assertEqual(result["endpoints"]["/api/v1/things/list"]["method"], "UNKNOWN")

    def test_only_portal_static_files_are_requested_and_never_an_api_path(self):
        site = FakeSite()
        self.scan(site)
        self.assertEqual(site.requests, ["https://rsp.simlessly.com/",
                                         "https://rsp.simlessly.com/assets/index-AAAAAAAA.js",
                                         "https://rsp.simlessly.com/assets/things-BBBBBBBB.js",
                                         "https://rsp.simlessly.com/assets/files-CCCCCCCC.js"])

    def test_output_is_deterministic(self):
        self.assertEqual(api_watch.dump_json(self.scan()), api_watch.dump_json(self.scan()))
        self.assertNotIn("AAAAAAAA", api_watch.dump_json(self.scan()))          # no chunk hashes

    def test_unrecognized_structure_fails(self):
        site = FakeSite()
        site.pages["https://rsp.simlessly.com/"] = "<html><body>no scripts</body></html>"
        with small_limits(), self.assertRaisesRegex(api_watch.WatchError, "no module script"):
            api_watch.scan_portal(site)
        site = FakeSite()
        site.pages["https://rsp.simlessly.com/assets/index-AAAAAAAA.js"] = "<!DOCTYPE html><html></html>"
        with small_limits(), self.assertRaisesRegex(api_watch.WatchError, "not a JavaScript file"):
            api_watch.scan_portal(site)
        with small_limits(), self.assertRaisesRegex(api_watch.WatchError, "request helpers"):
            api_watch.scan_portal(FakeSite(lambda n, t: t.replace(".params=", ".prms=")))
        with self.assertRaisesRegex(api_watch.WatchError, "only 12 /api/ paths"):
            api_watch.scan_portal(FakeSite())              # default minimum

    def test_module_names_lose_their_hash(self):
        self.assertEqual(api_watch.module_name("group-DIF3uJEs.js"), "group")
        self.assertEqual(api_watch.module_name("_plugin-vue_export-helper-DlAUqK2U.js"), "_plugin-vue_export-helper")
        self.assertEqual(api_watch.module_name("AdminClient-CLaa4DCK.js"), "AdminClient")


class FetchGuardTests(unittest.TestCase):
    def test_check_url(self):
        api_watch.check_url("https://docs.simlessly.com/rsp/api-reference/x.html")
        api_watch.check_url("https://rsp.simlessly.com/assets/index-AAAAAAAA.js")
        for url in ("https://rsp.simlessly.com/api/v1/user/login", "https://rsp.simlessly.com/api/", "https://docs.simlessly.com/api/x",
                    "http://docs.simlessly.com/", "https://example.com/", "https://rsp.simlessly.com.evil.test/",
                    "https://user@evil.test/", "ftp://docs.simlessly.com/"):
            with self.assertRaises(api_watch.WatchError, msg=url):
                api_watch.check_url(url)

    def test_the_fetcher_checks_before_any_network_use(self):
        with self.assertRaises(api_watch.WatchError):
            api_watch.Fetcher(delay=0)("https://rsp.simlessly.com/api/v1/fleet/list")


# ------------------------------------------------------------------ diff

def snapshots():
    with small_limits():
        site = FakeSite()
        return api_watch.collect_docs(site), api_watch.scan_portal(site)


GROUPS = {"session": {"/api/v1/account/login": "POST", "/api/v1/account/logout": "GET"},
          "read": {"/api/v1/things/list": "POST", "/api/v1/things/detail": "GET", "/api/v1/things/render": "POST"},
          "write": {"/api/v1/things/import": "POST", "/api/v1/things/delete": "POST"},
          "multipart": ["/api/v1/things/import"]}


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.docs, self.portal = snapshots()

    def report(self, new_docs=None, new_portal=None, rsp_paths=()):
        """The portal report when only the portal changed, else the documentation report."""
        if new_docs is None:
            return api_watch.build_report(self.portal, new_portal or self.portal, GROUPS)
        return api_watch.build_docs_report(self.docs, new_docs, set(rsp_paths))

    def test_identical_snapshots(self):
        self.assertEqual(self.report().strip(), "# API change report\n\nNo changes since the committed snapshot.")
        self.assertEqual(api_watch.build_docs_report(self.docs, self.docs, set()).strip(),
                         "# Documentation change report\n\nNo changes since the stored snapshot.")

    def test_the_portal_report_does_not_mention_the_documentation(self):
        new = copy.deepcopy(self.portal)
        new["endpoints"]["/api/v1/things/detail"].update(method="POST", transport="json")
        report = self.report(new_portal=new)
        self.assertNotIn("Documentation", report)
        self.assertNotIn("documentation", report)

    def test_portal_changes_are_listed(self):
        new = copy.deepcopy(self.portal)
        new["endpoints"]["/api/v1/things/detail"]["method"] = "POST"
        new["endpoints"]["/api/v1/things/detail"]["transport"] = "json"
        del new["endpoints"]["/api/v1/things/delete"]
        new["endpoints"]["/api/v1/things/new"] = {"method": "POST", "transport": "json", "modules": ["things"]}
        new["session_invalid_codes"] = ["20001"]
        report = self.report(new_portal=new)
        self.assertIn("1 paths added, 1 removed, 1 changed", report)
        self.assertIn("`/api/v1/things/detail` (used by the CLI): method changed from GET to POST", report)
        self.assertIn("`POST /api/v1/things/new` in `things`", report)
        self.assertIn("`POST /api/v1/things/delete` (used by the CLI)", report)
        self.assertIn("session-invalid codes changed", report)
        self.assertIn("## Needs manual follow-up", report)
        self.assertIn("Portal path `/api/v1/things/delete` (write group) is no longer called", report)

    def test_documentation_changes_are_listed(self):
        new = copy.deepcopy(self.docs)
        e = new["pages"]["/rsp/api-reference/items/list-things.html"]["endpoints"][0]
        e["request"].append({"name": "limit", "type": "Integer", "required": False})
        e["request"][1]["type"] = "Object"
        del e["response"][0]
        e["url"] = "https://rsp.example.test/api/v1/things/list2"
        del new["pages"]["/cmp/api-reference/token.html"]
        report = self.report(new_docs=new, rsp_paths={"/api/v1/things/list"})
        self.assertIn("### Removed endpoints", report)
        self.assertIn("### New endpoints", report)
        self.assertIn("`POST https://rsp.example.test/api/v1/things/list2`", report)
        self.assertIn("`POST https://cmp.example.test/api/v1/external/token` (cmp, `Get Token`)", report)
        self.assertIn("Documentation for `POST https://rsp.example.test/api/v1/things/list`, which the CLI calls, was removed", report)
        # same endpoint with the same url, changed fields
        new2 = copy.deepcopy(self.docs)
        e2 = new2["pages"]["/rsp/api-reference/items/list-things.html"]["endpoints"][0]
        e2["request"].append({"name": "limit", "type": "Integer", "required": False})
        e2["request"][1]["type"] = "Object"
        del e2["response"][0]
        e2["response_types"]["PageParam"][0]["required"] = False
        report = self.report(new_docs=new2, rsp_paths={"/api/v1/things/list"})
        self.assertIn("request: added field `limit (Integer, optional)`", report)
        self.assertIn("request: field `pageParam` changed from `pageParam (PageParam, required)` to `pageParam (Object, required)`", report)
        self.assertIn("response: removed field `pageParam (PageParam, required)`", report)
        self.assertIn("response type `PageParam`: field `pageNum` changed", report)
        self.assertIn("which the CLI calls, changed", report)

    def test_scraped_text_cannot_inject_markup_or_mentions(self):
        new = copy.deepcopy(self.docs)
        e = new["pages"]["/rsp/api-reference/items/list-things.html"]["endpoints"][0]
        e["request"].append({"name": "x`\n@owner [a](http://x.test) <b>", "type": "T", "required": True})
        report = self.report(new_docs=new)
        for line in report.splitlines():
            if "added field" in line:
                self.assertEqual(line.count("`"), 2, line)                # one code span, nothing outside it
                self.assertNotIn("\n", line)
                self.assertTrue(line.index("@owner") > line.index("`"))
        self.assertNotIn("\n@owner", report)

    def test_scraped_type_names_stay_inside_code_spans(self):
        payload = "@someone [click](https://evil.test) <img src=x>"
        old = copy.deepcopy(self.docs)
        e = old["pages"]["/rsp/api-reference/items/list-things.html"]["endpoints"][0]
        e["response_types"] = {payload: [{"name": "a", "type": "T", "required": True}]}
        e["request_types"] = {payload: [{"name": "a", "type": "T", "required": True}]}
        new = copy.deepcopy(old)
        for key in ("response_types", "request_types"):
            new["pages"]["/rsp/api-reference/items/list-things.html"]["endpoints"][0][key][payload].append(
                {"name": "b", "type": "T", "required": True})
        report = api_watch.build_docs_report(old, new, set())
        lines = [line for line in report.splitlines() if "added field `b" in line]
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertLess(line.index("`"), line.index("@someone"))
            self.assertNotIn("<img", line.split("`")[0] + line.split("`")[-1])
            self.assertEqual(line.count("`"), 4, line)               # the type name and the field, both in code spans

    def test_page_module_changes_alone_are_not_a_change(self):
        new = copy.deepcopy(self.portal)
        for entry in new["endpoints"].values():
            entry["modules"] = ["somewhere-else"]
        self.assertTrue(api_watch.same_portal(self.portal, new))
        self.assertEqual(self.report(new_portal=new).strip(), "# API change report\n\nNo changes since the committed snapshot.")
        new["endpoints"]["/api/v1/things/detail"]["method"] = "POST"
        self.assertFalse(api_watch.same_portal(self.portal, new))
        report = self.report(new_portal=new)
        self.assertNotIn("page modules", report)
        self.assertIn("method changed from GET to POST", report)

    def test_long_reports_are_capped(self):
        text = "x\n" * (api_watch.REPORT_LIMIT)
        capped = api_watch.cap_report(text)
        self.assertLess(len(capped), api_watch.REPORT_LIMIT + 200)
        self.assertIn("Report shortened", capped)
        self.assertIn("api-snapshot/", capped)
        self.assertNotIn("api-snapshot/", api_watch.cap_report(text, "The stored snapshot has the full data."))
        self.assertEqual(api_watch.cap_report("short"), "short")


# ------------------------------------------------------------------ apply

class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.docs, self.portal = snapshots()
        # a portal snapshot that matches GROUPS exactly
        self.portal["endpoints"] = {
            "/api/v1/account/login": {"method": "POST", "transport": "json", "modules": ["index"]},
            "/api/v1/account/logout": {"method": "GET", "transport": "query", "modules": ["index"]},
            "/api/v1/things/list": {"method": "POST", "transport": "json", "modules": ["things"]},
            "/api/v1/things/detail": {"method": "GET", "transport": "query", "modules": ["things"]},
            "/api/v1/things/render": {"method": "POST", "transport": "json", "modules": ["things"]},
            "/api/v1/things/import": {"method": "POST", "transport": "multipart", "modules": ["things"]},
            "/api/v1/things/delete": {"method": "POST", "transport": "json", "modules": ["things"]},
        }

    def apply(self, edit=None):
        new = copy.deepcopy(self.portal)
        if edit:
            edit(new["endpoints"])
        return api_watch.apply_methods(GROUPS, new)

    def test_nothing_changes_when_the_portal_matches(self):
        updated, plan = self.apply()
        self.assertEqual(updated, GROUPS)
        self.assertEqual(plan, {"applied": [], "skipped": [], "missing": []})

    def test_a_read_method_change_is_applied_in_place(self):
        def edit(eps):
            eps["/api/v1/things/detail"].update(method="POST", transport="json")
            eps["/api/v1/things/list"].update(method="GET", transport="query")
        updated, plan = self.apply(edit)
        self.assertEqual(updated["read"]["/api/v1/things/detail"], "POST")
        self.assertEqual(updated["read"]["/api/v1/things/list"], "GET")
        self.assertEqual(plan["applied"], [("read", "/api/v1/things/list", "POST", "GET"),
                                           ("read", "/api/v1/things/detail", "GET", "POST")])
        self.assertEqual(plan["skipped"], [])
        for group in ("session", "read", "write"):                       # same paths in the same groups
            self.assertEqual(list(updated[group]), list(GROUPS[group]))
        self.assertEqual(updated["multipart"], GROUPS["multipart"])
        self.assertEqual(GROUPS["read"]["/api/v1/things/detail"], "GET")  # the input is not modified

    def test_session_and_write_method_changes_are_reported_and_never_applied(self):
        # a GET login would put the credentials in the URL; a write that turns into a GET would be sent as one
        def edit(eps):
            eps["/api/v1/account/login"].update(method="GET", transport="query")
            eps["/api/v1/account/logout"].update(method="POST", transport="json")
            eps["/api/v1/things/delete"].update(method="GET", transport="query")
        updated, plan = self.apply(edit)
        self.assertEqual(updated, GROUPS)
        self.assertEqual(plan["applied"], [])
        self.assertEqual({p for p, _ in plan["skipped"]},
                         {"/api/v1/account/login", "/api/v1/account/logout", "/api/v1/things/delete"})
        new = copy.deepcopy(self.portal)
        edit(new["endpoints"])
        report = api_watch.build_report(self.portal, new, GROUPS)
        self.assertIn("## Needs manual follow-up", report)
        self.assertIn("Portal path `/api/v1/account/login` changed, not applied: its method changed from POST to GET "
                      "in the session group, which is only changed by hand.", report)
        self.assertIn("Portal path `/api/v1/things/delete` changed, not applied", report)

    def test_a_new_path_is_never_added(self):
        def edit(eps):
            eps["/api/v1/things/brand-new"] = {"method": "POST", "transport": "json", "modules": ["things"]}
            eps["/api/v1/block/add"] = {"method": "POST", "transport": "json", "modules": ["block"]}
        updated, plan = self.apply(edit)
        self.assertEqual(updated, GROUPS)
        self.assertEqual(plan["applied"], [])

    def test_a_removed_path_is_kept_and_reported(self):
        updated, plan = self.apply(lambda eps: eps.pop("/api/v1/things/render"))
        self.assertEqual(updated, GROUPS)
        self.assertEqual(plan["missing"], ["/api/v1/things/render"])
        old = copy.deepcopy(self.portal)
        new = copy.deepcopy(self.portal)
        del new["endpoints"]["/api/v1/things/render"]
        report = api_watch.build_report(old, new, GROUPS)
        self.assertIn("Portal path `/api/v1/things/render` (read group) is no longer called", report)

    def test_a_path_is_never_moved_between_groups(self):
        # the portal data has no notion of group; a change of use cannot move a path
        updated, _ = self.apply(lambda eps: eps["/api/v1/things/delete"].update(modules=["viewer"]))
        self.assertIn("/api/v1/things/delete", updated["write"])
        self.assertNotIn("/api/v1/things/delete", updated["read"])
        self.assertEqual({k: set(v) for k, v in updated.items()}, {k: set(v) for k, v in GROUPS.items()})

    def test_transport_changes_and_unclassified_calls_are_reported_not_applied(self):
        def edit(eps):
            eps["/api/v1/things/import"].update(transport="json")                    # upload became JSON
            eps["/api/v1/things/list"].update(method="POST", transport="multipart")  # JSON became upload
            eps["/api/v1/things/detail"].update(method="CONFLICT", transport="json|query")
            eps["/api/v1/things/render"].update(method="UNKNOWN", transport="unresolved")
            eps["/api/v1/account/logout"].update(method="GET", transport="navigation")
        updated, plan = self.apply(edit)
        self.assertEqual(updated, GROUPS)
        self.assertEqual({p for p, _ in plan["skipped"]},
                         {"/api/v1/things/import", "/api/v1/things/list", "/api/v1/things/detail",
                          "/api/v1/things/render", "/api/v1/account/logout"})
        new = copy.deepcopy(self.portal)
        edit(new["endpoints"])
        report = api_watch.build_report(self.portal, new, GROUPS)
        self.assertIn("changed, not applied", report)

    def test_a_multipart_path_keeps_its_method_when_only_modules_change(self):
        updated, plan = self.apply(lambda eps: eps["/api/v1/things/import"].update(modules=["other"]))
        self.assertEqual((updated, plan["applied"], plan["skipped"]), (GROUPS, [], []))

    def test_apply_is_idempotent(self):
        def edit(eps):
            eps["/api/v1/things/detail"].update(method="POST", transport="json")
        first, _ = self.apply(edit)
        again, plan = api_watch.apply_methods(first, {"endpoints": {**self.portal["endpoints"],
                                                                    "/api/v1/things/detail": {"method": "POST", "transport": "json", "modules": []}}})
        self.assertEqual(again, first)
        self.assertEqual(plan["applied"], [])


class SnapshotCheckTests(unittest.TestCase):
    """Guards against a snapshot that is a degraded reading of the sites, not an API change."""

    def setUp(self):
        self.docs, self.portal = snapshots()

    def check(self, portal=None, baseline="default", groups=GROUPS):
        api_watch.check_snapshot(portal or self.portal, self.portal if baseline == "default" else baseline, groups)

    def check_docs(self, docs, rsp=()):
        api_watch.check_docs(docs, self.docs, set(rsp))

    def test_an_unchanged_snapshot_passes(self):
        self.check()
        self.check(baseline=None)
        self.check_docs(self.docs)

    def test_a_cli_path_that_cannot_be_classified_is_refused_with_or_without_a_baseline(self):
        for method in ("UNKNOWN", "CONFLICT"):
            new = copy.deepcopy(self.portal)
            new["endpoints"]["/api/v1/things/list"].update(method=method)
            for baseline in ("default", None):
                with self.assertRaisesRegex(api_watch.WatchError, "could not be classified"):
                    self.check(portal=new, baseline=baseline)
        new = copy.deepcopy(self.portal)                       # a path the CLI does not use may be unclassified
        new["endpoints"]["/api/v1/files/list"].update(method="UNKNOWN")
        self.check(portal=new)

    def test_many_method_changes_at_once_are_refused(self):
        new = copy.deepcopy(self.portal)
        for path in ("/api/v1/things/detail", "/api/v1/things/list", "/api/v1/account/login"):
            new["endpoints"][path]["method"] = "GET" if new["endpoints"][path]["method"] == "POST" else "POST"
        with self.assertRaisesRegex(api_watch.WatchError, "3 of 12 paths changed at once"):
            self.check(portal=new)
        new = copy.deepcopy(self.portal)
        new["endpoints"]["/api/v1/things/detail"]["method"] = "POST"      # one of 12 is fine
        self.check(portal=new)

    def test_more_than_the_absolute_limit_of_method_changes_is_refused_in_a_large_snapshot(self):
        old = {"endpoints": {f"/api/v1/p/{i}": {"method": "POST", "transport": "json", "modules": []} for i in range(100)}}
        for count, ok in ((5, True), (6, False)):
            new = copy.deepcopy(old)
            for i in range(count):
                new["endpoints"][f"/api/v1/p/{i}"]["method"] = "GET"
            check = lambda: api_watch.check_snapshot(new, old, GROUPS)      # noqa: E731
            if ok:
                check()
            else:
                with self.assertRaisesRegex(api_watch.WatchError, "6 of 100 paths changed at once"):
                    check()

    def test_a_drop_in_documentation_endpoints_with_method_and_url_is_refused(self):
        new = copy.deepcopy(self.docs)
        for page in new["pages"].values():           # the same endpoints, but the headings are no longer recognized
            for e in page["endpoints"]:
                e["method"] = e["url"] = None
        self.assertEqual(api_watch.count_docs(new), api_watch.count_docs(self.docs))
        with self.assertRaisesRegex(api_watch.WatchError, "documentation endpoints with a method and URL"):
            self.check_docs(new)

    def test_a_drop_in_portal_paths_with_a_known_method_is_refused(self):
        new = copy.deepcopy(self.portal)
        for path in ("/api/v1/files/list", "/api/v1/owner/info", "/api/v1/site/info"):
            new["endpoints"][path].update(method="UNKNOWN", transport="unresolved")
        with self.assertRaisesRegex(api_watch.WatchError, "portal paths with a known method: 9 found, 12"):
            self.check(portal=new)

    def test_a_documented_cli_path_that_lost_its_method_is_refused_but_a_removed_one_is_reported(self):
        page = "/rsp/api-reference/items/list-things.html"
        degraded = copy.deepcopy(self.docs)
        e = degraded["pages"][page]["endpoints"][0]
        e["method"] = e["url"] = None
        with mock.patch.object(api_watch, "RESOLVED_DROP_LIMIT", 1.0):          # isolate this check from the count check
            with self.assertRaisesRegex(api_watch.WatchError, "lost the method or URL"):
                self.check_docs(degraded, rsp={"/api/v1/things/list"})
            self.check_docs(degraded)                                           # not a path the CLI calls
            removed = copy.deepcopy(self.docs)
            removed["pages"][page]["endpoints"] = []
            self.check_docs(removed, rsp={"/api/v1/things/list"})               # gone from the page: shown in the report
            del removed["pages"][page]
            self.check_docs(removed, rsp={"/api/v1/things/list"})

    def test_page_modules_of_unchanged_paths_are_kept(self):
        new = copy.deepcopy(self.portal)
        for entry in new["endpoints"].values():
            entry["modules"] = ["renamed-chunk"]
        new["endpoints"]["/api/v1/things/detail"].update(method="POST", transport="json")
        new["endpoints"]["/api/v1/brand/new"] = {"method": "POST", "transport": "json", "modules": ["renamed-chunk"]}
        api_watch.keep_known_modules(new, self.portal)
        self.assertEqual(new["endpoints"]["/api/v1/things/list"]["modules"], self.portal["endpoints"]["/api/v1/things/list"]["modules"])
        self.assertEqual(new["endpoints"]["/api/v1/things/detail"]["modules"], ["renamed-chunk"])
        self.assertEqual(new["endpoints"]["/api/v1/brand/new"]["modules"], ["renamed-chunk"])

    def test_broken_import_resolution_is_refused_by_the_portal_scan(self):
        with self.assertRaisesRegex(api_watch.WatchError, "could not be determined"):
            with small_limits():
                api_watch.scan_portal(FakeSite(lambda n, t: t.replace('from"./index-AAAAAAAA.js"', 'from"/assets/index-AAAAAAAA.js"')))


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="api-watch-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.endpoints = self.tmp / "portal_endpoints.json"
        self.endpoints.write_text(json.dumps(GROUPS, indent=2) + "\n")

    def run_main(self, *argv, fetch=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), small_limits(), \
                mock.patch.object(api_watch, "Fetcher", lambda **kw: fetch or FakeSite()):
            code = api_watch.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_snapshot_diff_apply_end_to_end(self):
        base, new = self.tmp / "base", self.tmp / "new"
        code, out, err = self.run_main("snapshot", "--out", str(base), "--baseline", str(self.tmp / "none"))
        self.assertEqual((code, err), (0, ""))
        self.assertTrue((base / "portal.json").read_text().endswith("\n"))
        self.assertEqual([f.name for f in base.iterdir()], ["portal.json"])          # no documentation content
        self.assertIn("12 portal paths", out)

        def edit(name, text):                                         # the portal flips one GET to POST
            return text.replace('function detail(e){return n("/api/v1/things/detail",e)}',
                                'function detail(e){return t("/api/v1/things/detail",e)}')
        code, out, err = self.run_main("snapshot", "--out", str(new), "--baseline", str(base), fetch=FakeSite(edit))
        self.assertEqual(code, 0, err)
        report = self.tmp / "report.md"
        code, out, err = self.run_main("diff", "--old", str(base), "--new", str(new), "--report", str(report))
        self.assertEqual((code, out), (0, ""))
        self.assertIn("snapshot differs", err)
        self.assertIn("`/api/v1/things/detail`: method changed from GET to POST", report.read_text())

        before = self.endpoints.read_text()
        code, out, err = self.run_main("apply", "--new", str(new), "--endpoints", str(self.endpoints), "--report", str(report))
        self.assertEqual(code, 0, err)
        self.assertIn("/api/v1/things/detail: GET -> POST", out)
        data = json.loads(self.endpoints.read_text())
        self.assertEqual(data["read"]["/api/v1/things/detail"], "POST")
        self.assertNotEqual(self.endpoints.read_text(), before)
        self.assertIn("## Applied automatically", report.read_text())
        self.assertIn("`/api/v1/things/detail` (read): GET to POST", report.read_text())
        self.assertIn("unit tests can fail until the request is adapted by hand", report.read_text())

        # a second run changes nothing
        code, out, err = self.run_main("apply", "--new", str(new), "--endpoints", str(self.endpoints))
        self.assertIn("0 method(s) updated", out)

    def test_a_cli_path_that_became_unclassifiable_is_refused_unless_forced(self):
        base, new = self.tmp / "base", self.tmp / "new"
        self.run_main("snapshot", "--out", str(base), "--baseline", str(self.tmp / "none"))

        def edit(name, text):
            return text.replace('return postj("/api/v1/account/login",e)', 'return mystery("/api/v1/account/login",e)')
        with mock.patch.object(api_watch, "MAX_UNCLASSIFIED_SHARE", 1.0):
            args = ("snapshot", "--out", str(new), "--baseline", str(base), "--endpoints", str(self.endpoints))
            code, out, err = self.run_main(*args, fetch=FakeSite(edit))
            self.assertEqual(code, 1)
            self.assertIn("/api/v1/account/login (session group) used by the CLI could not be classified", err)
            self.assertFalse(new.exists())
            code, out, err = self.run_main(*args, "--force", fetch=FakeSite(edit))
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads((new / "portal.json").read_text())["endpoints"]["/api/v1/account/login"]["method"], "UNKNOWN")

    def test_a_front_end_rebuild_that_only_renames_chunks_writes_the_same_snapshot(self):
        base, again = self.tmp / "base", self.tmp / "again"
        self.run_main("snapshot", "--out", str(base), "--baseline", str(self.tmp / "none"))
        data = json.loads((base / "portal.json").read_text())
        for entry in data["endpoints"].values():                 # the committed snapshot names other chunks
            entry["modules"] = ["older-chunk"]
        (base / "portal.json").write_text(api_watch.dump_json(data))
        code, out, err = self.run_main("snapshot", "--out", str(again), "--baseline", str(base))
        self.assertEqual(code, 0, err)
        self.assertEqual((again / "portal.json").read_text(), (base / "portal.json").read_text())
        code, out, err = self.run_main("diff", "--old", str(base), "--new", str(again))
        self.assertIn("no changes", err)

    def test_diff_without_changes(self):
        base = self.tmp / "base"
        self.run_main("snapshot", "--out", str(base), "--baseline", str(self.tmp / "none"))
        code, out, err = self.run_main("diff", "--old", str(base), "--new", str(base))
        self.assertIn("No changes since the committed snapshot.", out)
        self.assertIn("no changes", err)

    def test_a_shrunk_snapshot_is_refused_and_nothing_is_written(self):
        base, new = self.tmp / "base", self.tmp / "new"
        self.run_main("snapshot", "--out", str(base), "--baseline", str(self.tmp / "none"))

        def gutted(name, text):
            if name.startswith("things"):
                return 'export{}'
            return text
        with small_limits():
            code, out, err = self.run_main("snapshot", "--out", str(new), "--baseline", str(base),
                                           fetch=FakeSite(gutted))
        self.assertEqual(code, 1)
        self.assertIn("refusing to write", err)
        self.assertFalse(new.exists())

    def test_a_scrape_failure_exits_non_zero_and_writes_nothing(self):
        site = FakeSite()
        site.pages["https://rsp.simlessly.com/"] = "<html></html>"
        new = self.tmp / "new"
        code, out, err = self.run_main("snapshot", "--out", str(new), "--baseline", str(self.tmp / "none"), fetch=site)
        self.assertEqual(code, 1)
        self.assertIn("api_watch: error:", err)
        self.assertFalse(new.exists())


# ------------------------------------------------------------------ docs-check

TOKEN = "SESSIONTOKEN-do-not-leak-0123456789"
POSIX = os.name == "posix"
ROOT_DIR = Path(__file__).resolve().parent.parent
QUERY_ORDER = "/api/v1/plan/queryOrder"
LIST_THINGS = "/rsp/api-reference/items/list-things.html"
SIGN_IN = "sign in first: simlessly portal login"


class _Response:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit=None):
        return self.body[:limit]


class FakeOpener:
    """Stands in for the urllib opener: serves the fixture site and keeps every Request."""

    def __init__(self, site):
        self.site = site
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if request.full_url not in self.site.pages:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)
        return _Response(self.site.pages[request.full_url].encode("utf-8"))


class FetcherSessionTests(unittest.TestCase):
    def fetch(self, url, token):
        opener = FakeOpener(FakeSite())
        fetcher = api_watch.Fetcher(delay=0, session_token=token)
        fetcher._opener = opener
        fetcher(url)
        return opener.requests[0]

    def test_the_session_is_sent_as_a_cookie_to_the_documentation_host_only(self):
        request = self.fetch("https://docs.simlessly.com/", TOKEN)
        self.assertEqual(request.get_header("Cookie"), "simlessly_token=" + TOKEN)
        self.assertIsNone(self.fetch("https://rsp.simlessly.com/", TOKEN).get_header("Cookie"))
        self.assertIsNone(self.fetch("https://docs.simlessly.com/", None).get_header("Cookie"))


class DocsCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="docs-check-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.portal = MockPortal()
        self.addCleanup(self.portal.close)
        self.fetched_before_session_check = []
        self.session_answer = None            # None: valid session; else the failure envelope code
        self.portal.routes[QUERY_ORDER] = self.session_route
        self.site = FakeSite()
        self.opener = FakeOpener(self.site)
        self.snapshot = self.tmp / "private" / "docs-snapshot.json"
        self.env = {"SIMLESSLY_PORTAL_TOKEN": TOKEN, "SIMLESSLY_BASE_URL": self.portal.url,
                    "SIMLESSLY_NO_KEYCHAIN": "1", "SIMLESSLY_NO_CREDENTIALS_FILE": "1",
                    "SIMLESSLY_DOCS_SNAPSHOT": str(self.snapshot)}

    def session_route(self, rec):
        self.fetched_before_session_check.append(len(self.opener.requests))
        if self.session_answer:
            return 200, envelope(None, False, "user token invalid, please login first", self.session_answer), {}
        if rec.headers.get("Simlessly-Token") != TOKEN:
            return 200, envelope(None, False, "user token invalid, please login first", "10206"), {}
        return ok({"planType": "PRO", "status": "ACTIVE"})

    def run_check(self, *argv, env=None, drop=()):
        environment = dict(self.env if env is None else env)
        for name in drop:
            environment.pop(name, None)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), small_limits(), \
                mock.patch.dict(os.environ, environment), \
                mock.patch.object(api_watch.time, "sleep"), \
                mock.patch.object(api_watch.urllib.request, "build_opener", lambda *a: self.opener):
            if "SIMLESSLY_PORTAL_TOKEN" not in environment:
                os.environ.pop("SIMLESSLY_PORTAL_TOKEN", None)
            code = api_watch.main(["docs-check", *argv])
        return code, out.getvalue(), err.getvalue()

    def assertNothingFetched(self):
        self.assertEqual(self.opener.requests, [])

    def assertNoToken(self, *texts):
        for text in texts:
            self.assertNotIn(TOKEN, text)

    def snapshot_text(self):
        return self.snapshot.read_text(encoding="utf-8")

    # ---- the session gate

    def test_no_stored_session_is_refused_before_anything_is_requested(self):
        code, out, err = self.run_check("--update", drop=("SIMLESSLY_PORTAL_TOKEN",))
        self.assertEqual((code, out), (1, ""))
        self.assertIn(SIGN_IN, err)
        self.assertEqual(self.portal.requests, [])
        self.assertNothingFetched()
        self.assertFalse(self.snapshot.parent.exists())

    def test_an_invalid_session_is_refused_and_no_documentation_is_fetched(self):
        for code_in_answer in ("10206", "10103", "10102"):
            self.session_answer = code_in_answer
            code, out, err = self.run_check("--update")
            self.assertEqual((code, out), (1, ""), code_in_answer)
            self.assertIn(SIGN_IN, err)
            self.assertNoToken(err)
            self.assertNothingFetched()
            self.assertFalse(self.snapshot.parent.exists())
        self.assertEqual(len(self.portal.requests), 3)

    def test_a_token_that_cannot_be_sent_as_a_cookie_is_refused_without_a_request(self):
        for bad in ("abc;def", "abc def", 'abc"def', "tok\u00e9n"):
            code, out, err = self.run_check("--update", env={**self.env, "SIMLESSLY_PORTAL_TOKEN": bad})
            self.assertEqual(code, 1, bad)
            self.assertIn(SIGN_IN, err)
        self.assertEqual(self.portal.requests, [])
        self.assertNothingFetched()

    def test_a_failed_check_that_is_not_a_session_problem_does_not_ask_for_a_login(self):
        self.session_answer = "50000"
        code, out, err = self.run_check("--update")
        self.assertEqual(code, 1)
        self.assertIn("could not check the portal session", err)
        self.assertNotIn("sign in first", err)
        self.assertNothingFetched()

    def test_the_session_is_checked_like_the_documentation_site_does_and_before_the_pages(self):
        code, out, err = self.run_check("--update")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(self.portal.requests), 1)
        request = self.portal.requests[0]
        self.assertEqual((request.method, request.path, request.body), ("POST", QUERY_ORDER, "{}"))
        self.assertEqual(request.headers["Simlessly-Token"], TOKEN)
        self.assertEqual(request.problems, [])
        self.assertEqual(self.fetched_before_session_check, [0])             # no page was requested before the check
        self.assertIn(QUERY_ORDER, api_watch._cli_modules()[3].READ_METHODS)   # reached through the CLI's read allowlist
        self.assertEqual(api_watch._cli_modules()[3].READ_METHODS[QUERY_ORDER], "POST")

    # ---- fetching

    def test_the_documentation_is_fetched_with_the_session_cookie(self):
        code, out, err = self.run_check("--update")
        self.assertEqual(code, 0, err)
        self.assertTrue(self.opener.requests)
        for request in self.opener.requests:
            self.assertTrue(request.full_url.startswith("https://docs.simlessly.com/"), request.full_url)
            self.assertEqual(request.get_header("Cookie"), "simlessly_token=" + TOKEN)
            self.assertEqual(request.get_method(), "GET")

    # ---- the private snapshot

    def test_the_snapshot_is_written_outside_the_repository_for_the_owner_only(self):
        code, out, err = self.run_check("--update")
        self.assertEqual(code, 0, err)
        self.assertIn(f"documentation snapshot written to {self.snapshot.resolve()}", out)
        with small_limits():
            expected = api_watch.collect_docs(FakeSite())
        self.assertEqual(json.loads(self.snapshot_text()), expected)
        if POSIX:
            self.assertEqual(stat.S_IMODE(self.snapshot.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.snapshot.parent.stat().st_mode), 0o700)
        self.assertEqual([f.name for f in self.snapshot.parent.iterdir()], ["docs-snapshot.json"])    # no temp file left
        self.assertIsNone(api_watch.work_tree_of(self.snapshot))
        self.assertNoToken(out, err, self.snapshot_text())

    def test_every_new_directory_on_the_way_is_private(self):
        deep = self.tmp / "a" / "b" / "docs-snapshot.json"
        code, out, err = self.run_check("--update", env={**self.env, "SIMLESSLY_DOCS_SNAPSHOT": str(deep)})
        self.assertEqual(code, 0, err)
        if POSIX:
            for directory in (deep.parent, deep.parent.parent):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700, directory)
            self.assertEqual(stat.S_IMODE(deep.stat().st_mode), 0o600)

    def test_the_default_location_is_in_the_config_directory(self):
        home = self.tmp / "home"
        config = home / ".config" / "simlessly-cli"
        config.mkdir(parents=True)
        if POSIX:
            config.chmod(0o755)
        env = {**self.env, "HOME": str(home), "USERPROFILE": str(home)}
        del env["SIMLESSLY_DOCS_SNAPSHOT"]
        code, out, err = self.run_check("--update", env=env, drop=("XDG_CONFIG_HOME",))
        self.assertEqual(code, 0, err)
        self.assertTrue((config / "docs-snapshot.json").is_file())
        if POSIX:
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o700)           # the default directory is tightened
            self.assertEqual(stat.S_IMODE((config / "docs-snapshot.json").stat().st_mode), 0o600)
        # $XDG_CONFIG_HOME moves it, as it moves the credentials file
        xdg = self.tmp / "xdg"
        code, out, err = self.run_check("--update", env={**env, "XDG_CONFIG_HOME": str(xdg)})
        self.assertEqual(code, 0, err)
        self.assertTrue((xdg / "simlessly-cli" / "docs-snapshot.json").is_file())

    @unittest.skipUnless(POSIX, "directory modes")
    def test_a_directory_chosen_by_the_user_is_not_changed_only_reported(self):
        shared = self.tmp / "shared"
        shared.mkdir()
        shared.chmod(0o755)
        code, out, err = self.run_check("--update", env={**self.env, "SIMLESSLY_DOCS_SNAPSHOT": str(shared / "d.json")})
        self.assertEqual(code, 0)
        self.assertEqual(stat.S_IMODE(shared.stat().st_mode), 0o755)
        self.assertIn("can be read by other users", err)

    def test_a_path_inside_the_repository_or_any_git_work_tree_is_refused(self):
        other_tree = self.tmp / "other"
        (other_tree / ".git").mkdir(parents=True)
        link = self.tmp / "link"
        try:
            link.symlink_to(ROOT_DIR, target_is_directory=True)
            linked = [link / "docs-snapshot.json"]
        except (OSError, NotImplementedError):
            linked = []
        for path in (ROOT_DIR / "docs-snapshot.json", ROOT_DIR / "api-snapshot" / "docs.json",
                     ROOT_DIR / "new-dir" / "d.json", other_tree / "sub" / "d.json", *linked):
            code, out, err = self.run_check("--update", env={**self.env, "SIMLESSLY_DOCS_SNAPSHOT": str(path)})
            self.assertEqual((code, out), (1, ""), path)
            self.assertIn("inside the git work tree", err)
            self.assertFalse(path.exists(), path)
        self.assertFalse((other_tree / "sub").exists())
        self.assertFalse((ROOT_DIR / "new-dir").exists())
        self.assertEqual(self.portal.requests, [])                              # refused before the session was used
        self.assertNothingFetched()

    def test_a_report_file_inside_a_work_tree_is_refused(self):
        self.run_check("--update")
        other_tree = self.tmp / "other"
        (other_tree / ".git").mkdir(parents=True)
        for path in (ROOT_DIR / "report.md", other_tree / "report.md"):
            code, out, err = self.run_check("--report", str(path))
            self.assertEqual(code, 1)
            self.assertIn("refusing to write the report", err)
            self.assertFalse(path.exists())

    # ---- update and report

    def test_report_and_update_exit_codes(self):
        code, out, err = self.run_check()                                       # nothing stored yet
        self.assertEqual((code, out), (1, ""))
        self.assertIn("no documentation snapshot", err)
        self.assertIn("docs-check --update", err)

        code, out, err = self.run_check("--update")
        self.assertEqual(code, 0, err)
        code, out, err = self.run_check()
        self.assertEqual(code, 0, err)
        self.assertIn("No changes since the stored snapshot.", out)
        self.assertIn("no changes", err)

        stored = json.loads(self.snapshot_text())                               # the documentation moved on since then
        stored["pages"][LIST_THINGS]["endpoints"][0]["request"][0]["type"] = "Text"
        self.snapshot.write_text(api_watch.dump_json(stored), encoding="utf-8")
        before = self.snapshot_text()
        code, out, err = self.run_check()
        self.assertEqual(code, 1, err)
        self.assertIn("# Documentation change report", out)
        self.assertIn("request: field `nameFilter` changed from `nameFilter (Text, optional)` to `nameFilter (String, optional)`", out)
        self.assertIn("documentation differs from the stored snapshot", err)
        self.assertEqual(self.snapshot_text(), before)                          # a report never rewrites the snapshot

        code, out, err = self.run_check("--update")
        self.assertEqual(code, 0, err)
        self.assertIn("1 changed", out)
        self.assertNotEqual(self.snapshot_text(), before)
        self.assertEqual(self.run_check()[0], 0)

    def test_the_report_can_go_to_a_file_outside_the_repository(self):
        self.run_check("--update")
        stored = json.loads(self.snapshot_text())
        stored["pages"][LIST_THINGS]["endpoints"][0]["request"][0]["type"] = "Text"
        self.snapshot.write_text(api_watch.dump_json(stored), encoding="utf-8")
        report = self.tmp / "report.md"
        code, out, err = self.run_check("--report", str(report))
        self.assertEqual((code, out), (1, ""))
        self.assertIn("changed from", report.read_text(encoding="utf-8"))
        if POSIX:
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertNoToken(report.read_text(encoding="utf-8"), err)

    def test_update_and_report_cannot_be_combined(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            api_watch.main(["docs-check", "--update", "--report", "x.md"])

    def test_a_degraded_reading_is_not_used_unless_forced(self):
        self.run_check("--update")
        stored = json.loads(self.snapshot_text())
        extra = [{**copy.deepcopy(stored["pages"][LIST_THINGS]["endpoints"][0]), "url": f"https://rsp.example.test/api/v1/x/{i}",
                  "title": f"X{i}"} for i in range(40)]
        stored["pages"]["/rsp/api-reference/items/extra.html"] = {"title": "Extra", "endpoints": extra}
        self.snapshot.write_text(api_watch.dump_json(stored), encoding="utf-8")
        before = self.snapshot_text()
        for argv in ((), ("--update",)):
            code, out, err = self.run_check(*argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("refusing to use it", err)
            self.assertEqual(self.snapshot_text(), before)
        code, out, err = self.run_check("--update", "--force")
        self.assertEqual(code, 0, err)
        self.assertNotIn("extra.html", self.snapshot_text())

    def test_an_unreadable_stored_snapshot_is_reported_and_can_be_replaced_with_force(self):
        self.snapshot.parent.mkdir(mode=0o700)
        for content in ("{", '{"schema": 1, "pages": []}'):
            self.snapshot.write_text(content, encoding="utf-8")
            code, out, err = self.run_check()
            self.assertEqual(code, 1, content)
            self.assertIn("Delete it, or run docs-check --update --force", err)
        self.snapshot.write_text(api_watch.dump_json({"schema": 1, "pages": {"/x": {}}, "unavailable": []}), encoding="utf-8")
        code, out, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("unexpected structure", err)
        code, out, err = self.run_check("--update", "--force")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.run_check()[0], 0)

    def test_a_failed_page_fetch_is_an_error_not_a_change_and_the_snapshot_is_kept(self):
        self.run_check("--update")
        before = self.snapshot_text()
        self.site.pages.pop("https://docs.simlessly.com/")
        code, out, err = self.run_check()
        self.assertEqual((code, out), (1, ""))
        self.assertIn("api_watch: error:", err)
        self.assertEqual(self.snapshot_text(), before)

    def test_the_token_is_never_printed_or_stored(self):
        outputs = []
        self.session_answer = "10206"
        outputs += self.run_check("--update")[1:]
        self.session_answer = None
        outputs += self.run_check("--update")[1:]
        outputs += self.run_check()[1:]
        self.site.pages.pop("https://docs.simlessly.com/")
        outputs += self.run_check()[1:]
        self.assertNoToken(*outputs, self.snapshot_text())
        for request in self.opener.requests:                                    # only the cookie carries it
            self.assertNotIn(TOKEN, request.full_url)
            self.assertEqual([k for k, v in request.header_items() if TOKEN in v], ["Cookie"])


class RepositoryDataTests(unittest.TestCase):
    """The committed snapshot and the CLI's endpoint data."""

    ROOT = Path(__file__).resolve().parent.parent

    def test_the_cli_endpoint_file_is_what_apply_edits(self):
        groups = api_watch.load_endpoint_groups(ENDPOINTS_FILE)
        self.assertEqual(set(groups), {"session", "read", "write", "multipart"})
        paths = api_watch.cli_portal_paths(groups)
        self.assertEqual(len(paths), sum(len(groups[g]) for g in ("session", "read", "write")))     # no path in two groups

    def test_the_committed_snapshot_has_every_cli_path_with_a_compatible_transport(self):
        portal = api_watch.load_snapshot(self.ROOT / "api-snapshot")
        groups = api_watch.load_endpoint_groups(ENDPOINTS_FILE)
        plan = api_watch.plan_apply(groups, portal)
        self.assertEqual(plan, {"applied": [], "skipped": [], "missing": []})

    def test_no_documentation_content_is_in_the_repository(self):
        self.assertEqual(sorted(f.name for f in (self.ROOT / "api-snapshot").iterdir()), ["portal.json"])
        ignored = (self.ROOT / ".gitignore").read_text(encoding="utf-8").split()
        self.assertIn("docs-snapshot.json", ignored)
        self.assertIn("api-snapshot/docs.json", ignored)


class WorkflowTests(unittest.TestCase):
    """The workflow cannot be run here; these checks keep its safety properties from being edited away."""

    TEXT = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / "api-watch.yml").read_text(encoding="utf-8")

    def test_the_token_is_not_stored_and_only_the_last_steps_receive_it(self):
        self.assertIn("persist-credentials: false", self.TEXT)
        steps = self.TEXT.split("      - name: ")[1:]
        with_token = [step.splitlines()[0] for step in steps if "GH_TOKEN" in step]
        self.assertEqual(with_token, ["Open or update the pull request", "Close an outdated pull request"])
        for step in steps:
            if "api_watch.py" in step or "unittest" in step:
                self.assertNotIn("GH_TOKEN", step)

    def test_the_branch_is_never_force_pushed_over_other_commits(self):
        self.assertNotIn("--force origin", self.TEXT)
        self.assertIn("--force-with-lease=", self.TEXT)
        self.assertIn("grep -vxF", self.TEXT)                         # commits by anyone but the bot
        self.assertIn("hand_edited", self.TEXT)

    def test_pull_request_state_follows_the_tests_and_the_changes(self):
        self.assertIn("gh pr ready --undo", self.TEXT)
        self.assertIn("gh pr close", self.TEXT)
        self.assertIn("gh pr create --draft", self.TEXT)

    def test_the_workflow_covers_the_portal_only(self):
        for word in ("docs.json", "docs-check", "docs-snapshot"):
            self.assertNotIn(word, self.TEXT)
        self.assertNotIn("docs.simlessly.com", self.TEXT)
        self.assertIn("api-new/portal.json", self.TEXT)

    def test_no_expression_is_expanded_inside_a_run_script(self):
        for step in self.TEXT.split("      - name: ")[1:]:
            if "run:" in step:
                script = step.split("run:", 1)[1]
                self.assertNotIn("${{", script)

    def test_actions_are_pinned_to_a_commit(self):
        import re
        for line in self.TEXT.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses: [\w.\-]+/[\w.\-]+@[0-9a-f]{40}\b")


if __name__ == "__main__":
    unittest.main()
