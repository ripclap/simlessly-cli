"""tools/api_watch.py: snapshot extraction, diff and apply, offline against small fabricated pages and scripts."""

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import support  # noqa: F401  (network guard: any real request fails the test)

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
        return api_watch.build_report(self.docs, new_docs or self.docs, self.portal, new_portal or self.portal,
                                      GROUPS, set(rsp_paths))

    def test_identical_snapshots(self):
        self.assertEqual(self.report().strip(), "# API change report\n\nNo changes since the committed snapshot.")

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
        report = api_watch.build_report(old, new, self.portal, self.portal, GROUPS, set())
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
        report = api_watch.build_report(self.docs, self.docs, self.portal, new, GROUPS, set())
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
        report = api_watch.build_report(self.docs, self.docs, old, new, GROUPS, set())
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
        report = api_watch.build_report(self.docs, self.docs, self.portal, new, GROUPS, set())
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
        self.baseline = (self.docs, self.portal)

    def check(self, docs=None, portal=None, baseline="default", groups=GROUPS, rsp=()):
        api_watch.check_snapshot(docs or self.docs, portal or self.portal,
                                 self.baseline if baseline == "default" else baseline, groups, set(rsp))

    def test_an_unchanged_snapshot_passes(self):
        self.check()
        self.check(baseline=None)

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
            check = lambda: api_watch.check_snapshot(self.docs, new, (self.docs, old), GROUPS, set())      # noqa: E731
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
            self.check(docs=new)

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
                self.check(docs=degraded, rsp={"/api/v1/things/list"})
            self.check(docs=degraded)                                           # not a path the CLI calls
            removed = copy.deepcopy(self.docs)
            removed["pages"][page]["endpoints"] = []
            self.check(docs=removed, rsp={"/api/v1/things/list"})               # gone from the page: shown in the report
            del removed["pages"][page]
            self.check(docs=removed, rsp={"/api/v1/things/list"})

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
                mock.patch.object(api_watch, "Fetcher", lambda: fetch or FakeSite()):
            code = api_watch.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_snapshot_diff_apply_end_to_end(self):
        base, new = self.tmp / "base", self.tmp / "new"
        code, out, err = self.run_main("snapshot", "--out", str(base), "--baseline", str(self.tmp / "none"))
        self.assertEqual((code, err), (0, ""))
        self.assertTrue((base / "docs.json").read_text().endswith("\n"))
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
        self.assertEqual((again / "docs.json").read_text(), (base / "docs.json").read_text())
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


class RepositoryDataTests(unittest.TestCase):
    """The committed snapshot and the CLI's endpoint data."""

    def test_the_cli_endpoint_file_is_what_apply_edits(self):
        groups = api_watch.load_endpoint_groups(ENDPOINTS_FILE)
        self.assertEqual(set(groups), {"session", "read", "write", "multipart"})
        paths = api_watch.cli_portal_paths(groups)
        self.assertEqual(len(paths), sum(len(groups[g]) for g in ("session", "read", "write")))     # no path in two groups

    def test_the_committed_snapshot_has_every_cli_path_with_a_compatible_transport(self):
        snapshot = Path(__file__).resolve().parent.parent / "api-snapshot"
        docs, portal = api_watch.load_snapshot(snapshot)
        groups = api_watch.load_endpoint_groups(ENDPOINTS_FILE)
        plan = api_watch.plan_apply(groups, portal)
        self.assertEqual(plan, {"applied": [], "skipped": [], "missing": []})
        self.assertGreater(api_watch.count_docs(docs), 10)
        rsp = api_watch.cli_rsp_paths()
        documented = {api_watch._url_path(e["url"]) for e in api_watch._docs_endpoints(docs).values()}
        self.assertEqual(rsp - documented, set(), "documented RSP paths used by the CLI")


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

    def test_actions_are_pinned_to_a_commit(self):
        import re
        for line in self.TEXT.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses: [\w.\-]+/[\w.\-]+@[0-9a-f]{40}\b")


if __name__ == "__main__":
    unittest.main()
