#!/usr/bin/env python3
"""Watch the Simlessly web portal's API calls, and (locally, signed in) the API documentation.

Commands used by the weekly GitHub job. They cover the web portal only:

  snapshot     Fetch the portal's front-end files and write api-snapshot/portal.json (every /api/ path
               the portal front-end calls, with its HTTP method).
  diff         Compare a new snapshot with the committed one and write a Markdown report.
  apply        Update the HTTP method of portal paths in the CLI's read group
               (src/simlessly_cli/portal_endpoints.json) when the portal changed it. It never adds
               a path, never moves a path between groups, and never changes the session or write
               groups (those are reported for a person to handle).

Command for a customer on their own machine:

  docs-check   Compare the API documentation with a private snapshot kept outside the repository.
               The documentation is for signed-in customers, so this needs a stored portal session
               (`simlessly portal login`). The snapshot and any report are never written inside a git
               work tree.

snapshot, diff and apply fetch only the portal's public static files. No /api/ endpoint is requested
and nothing is signed in. docs-check calls one /api/ path, the one the documentation site itself uses
to check the session. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_DIR = ROOT / "api-snapshot"
CONFIG_DIR_NAME = "simlessly-cli"
DOCS_SNAPSHOT_FILE = "docs-snapshot.json"
DOCS_SNAPSHOT_ENV = "SIMLESSLY_DOCS_SNAPSHOT"
SESSION_COOKIE = "simlessly_token"
SIGN_IN_FIRST = "sign in first: simlessly portal login"
ENDPOINTS_FILE = ROOT / "src" / "simlessly_cli" / "portal_endpoints.json"

DOCS_BASE = "https://docs.simlessly.com"
PORTAL_BASE = "https://rsp.simlessly.com"
ALLOWED_HOSTS = frozenset({"docs.simlessly.com", "rsp.simlessly.com"})
USER_AGENT = "simlessly-cli-api-watch (+https://github.com/ripclap/simlessly-cli)"
REQUEST_DELAY = 0.3          # seconds between requests
REQUEST_TIMEOUT = 30         # seconds
MAX_BYTES = 8 << 20

SCHEMA = 1
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
# A snapshot with far fewer entries than the stored one is treated as a failed scrape.
MIN_DOC_PAGES = 5
MIN_DOC_ENDPOINTS = 10
MIN_PORTAL_PATHS = 20
SHRINK_LIMIT = 0.5
# Further checks that a snapshot is a real reading of the sites and not a degraded one.
RESOLVED_DROP_LIMIT = 0.1    # share of documentation endpoints with method and URL, or portal paths with a method, that may vanish
MAX_METHOD_CHANGES = 5       # more portal method changes than this in one run is treated as a misreading
METHOD_CHANGE_SHARE = 0.1    # ... and so is a larger share of all portal paths
MAX_UNCLASSIFIED_SHARE = 0.05  # portal paths whose method is UNKNOWN or CONFLICT
REPORT_LIMIT = 60000         # characters; GitHub accepts 65536 in a PR body


class WatchError(Exception):
    """The site could not be fetched or its structure was not recognized."""


# ======================================================================================== fetching

class Fetcher:
    """Sequential, polite GET of pages. Callable: fetcher(url) -> text.

    With `session_token`, requests to the documentation host carry it as the simlessly_token cookie, as a
    signed-in browser sends it. It is never sent to another host, and redirects are not followed."""

    def __init__(self, delay: float = REQUEST_DELAY, timeout: float = REQUEST_TIMEOUT,
                 session_token: str | None = None) -> None:
        self.delay = delay
        self.timeout = timeout
        self._token = session_token
        self._last = 0.0
        self._opener = urllib.request.build_opener(_NoRedirect())

    def __call__(self, url: str) -> str:
        check_url(url)
        wait = self._last + self.delay - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        error: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(2.0 * attempt)
            headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*"}
            if self._token and urlsplit(url).hostname == urlsplit(DOCS_BASE).hostname:
                headers["Cookie"] = f"{SESSION_COOKIE}={self._token}"
            request = urllib.request.Request(url, headers=headers)
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    body = response.read(MAX_BYTES + 1)
                self._last = time.monotonic()
                if len(body) > MAX_BYTES:
                    raise WatchError(f"{url}: response larger than {MAX_BYTES} bytes")
                return body.decode("utf-8", "replace")
            except urllib.error.HTTPError as err:
                self._last = time.monotonic()
                if err.code == 404:
                    raise NotFound(url) from None
                if err.code < 500:
                    raise WatchError(f"{url}: HTTP {err.code}") from None
                error = err
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                self._last = time.monotonic()
                error = err
        raise WatchError(f"{url}: {error}")


class NotFound(WatchError):
    """HTTP 404 for a page."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def check_url(url: str) -> None:
    """Only https pages on the two Simlessly hosts, and never an /api/ path."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise WatchError(f"refusing to fetch {url}: not an https page on {', '.join(sorted(ALLOWED_HOSTS))}")
    if parts.path.startswith("/api/") or parts.path == "/api":
        raise WatchError(f"refusing to fetch {url}: /api/ paths are never requested")


# ======================================================================================== documentation

def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\xa0", " ")).strip()


class _PageParser(HTMLParser):
    """Reads one VuePress page: the h1 title, every link, and the blocks inside the content div.

    blocks: ("h", level, text) | ("t", text) for p and li | ("table", header, rows)
    """

    SKIP = ("script", "style", "svg", "pre")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.hrefs: list[str] = []
        self.blocks: list[tuple] = []
        self._in_content = False
        self._div_depth = 0
        self._skip: str | None = None
        self._skip_depth = 0
        self._cap: list[str] | None = None
        self._cap_kind = ""
        self._h1_title = False
        self._table: dict | None = None
        self._cell: list[str] | None = None
        self._row: list[str] | None = None

    # ---- tags
    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = {k: (v or "") for k, v in attrs}
        classes = a.get("class", "").split()
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        if self._skip:
            if tag == self._skip:
                self._skip_depth += 1
            return
        if tag in self.SKIP or (tag == "a" and "header-anchor" in classes) or "sr-only" in classes:
            self._skip, self._skip_depth = tag, 1
            return
        if tag == "h1" and "title" in classes and not self.title:
            self._h1_title, self._cap = True, []
            return
        if not self._in_content:
            if tag == "div" and "content__default" in classes:
                self._in_content, self._div_depth = True, 0
            return
        if tag == "div":
            self._div_depth += 1
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6", "p", "li") and self._table is None and self._cap is None:
            self._cap, self._cap_kind = [], tag
        elif tag == "table":
            self._table = {"header": None, "rows": []}
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("th", "td") and self._table is not None:
            self._cell = []
        elif tag == "br":
            self._add(" ")

    def handle_endtag(self, tag: str) -> None:
        if self._skip:
            if tag == self._skip:
                self._skip_depth -= 1
                if self._skip_depth == 0:
                    self._skip = None
            return
        if self._h1_title and tag == "h1":
            self.title = _clean("".join(self._cap or []))
            self._h1_title, self._cap = False, None
            return
        if not self._in_content:
            return
        if tag == "div":
            if self._div_depth == 0:
                self._in_content = False
            else:
                self._div_depth -= 1
        elif tag in ("th", "td") and self._cell is not None and self._row is not None:
            self._row.append(_clean("".join(self._cell)))
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            if self._row:
                if self._table["header"] is None and not self._table["rows"]:
                    self._table["header"] = self._row
                else:
                    self._table["rows"].append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            if self._table["header"] is not None:
                self.blocks.append(("table", self._table["header"], self._table["rows"]))
            self._table = None
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6", "p", "li") and self._cap is not None and self._cap_kind == tag:
            text = _clean("".join(self._cap))
            self._cap = None
            if text:
                self.blocks.append(("h", int(tag[1]), text) if tag[0] == "h" else ("t", text))

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._add(data)

    def _add(self, text: str) -> None:
        if self._cell is not None:
            self._cell.append(text)
        elif self._cap is not None:
            self._cap.append(text)


def parse_page(html: str) -> _PageParser | None:
    """The parsed page, or None when it is not a documentation page (the site answers unknown paths
    with its landing page and HTTP 200)."""
    parser = _PageParser()
    parser.feed(html)
    parser.close()
    return parser if parser.title and parser.blocks else None


_NAME_COLUMNS = {"name", "names", "parameter", "parameters", "param", "params", "field", "fields"}
_TYPE_COLUMNS = {"type", "data type", "datatype"}
_URL_RE = re.compile(r"https?://[^\s<>\"'`]+")
_LINE_ENDPOINT_RE = re.compile(r"\bEndpoint:\s*(GET|POST|PUT|PATCH|DELETE)\s+(\S+)", re.I)
_LINE_METHOD_RE = re.compile(r"\bHttp Method:\s*(GET|POST|PUT|PATCH|DELETE)\b\s*URL:\s*(?:\{\s*Base\s*Url\s*\})?\s*(\S*)", re.I)
_BASE_URL_RE = re.compile(r"\bBase URL:\s*(https?://\S+)", re.I)


def _required(value: str) -> bool | str | None:
    v = value.strip().lower()
    if not v:
        return None
    if v in ("m", "mandatory", "yes", "y", "required", "true"):
        return True
    if v in ("o", "optional", "no", "n", "false"):
        return False
    if v in ("c", "conditional"):
        return "conditional"
    return v


def _fields(header: list[str], rows: list[list[str]]) -> list[dict] | None:
    """Field list of a parameter table, or None when the table is something else."""
    low = [h.strip().lower().rstrip(":") for h in header]
    name = next((i for i, h in enumerate(low) if h in _NAME_COLUMNS), None)
    kind = next((i for i, h in enumerate(low) if h in _TYPE_COLUMNS), None)
    if name is None or kind is None:
        return None
    req = next((i for i, h in enumerate(low) if h in ("moc", "required", "mandatory", "mandatory/optional", "m/o",
                                                      "mandatory or optional", "optional")), None)
    out = []
    for row in rows:
        if len(row) <= max(name, kind) or not row[name]:
            continue
        out.append({"name": row[name], "type": row[kind],
                    "required": _required(row[req]) if req is not None and req < len(row) else None})
    out.sort(key=lambda f: (f["name"], f["type"], str(f["required"])))
    return out


def _role(heading: str) -> str | None:
    low = heading.lower()
    if "response" in low:
        return "response"
    if "request" in low:
        return "headers" if "header" in low else "request"
    return None


def extract_endpoints(blocks: list[tuple], product: str, page: str, page_title: str) -> list[dict]:
    """Endpoints described on one page. Three layouts occur: a method heading followed by the URL
    (RSP, eIM), an "Endpoint: METHOD /path" line under a base URL (newer RSP pages), and an
    "Http Method: ... URL:{BaseUrl}/path" line (CMP). A page with parameter tables but no endpoint
    (a webhook, a header description) yields one entry without method and URL."""
    endpoints: list[dict] = []
    cur: dict | None = None
    role: str | None = None
    type_name: str | None = None
    base_url: str | None = None
    awaiting_url = False
    prev_heading: tuple[int, str] | None = None

    def start(method: str | None, url: str | None, title: str) -> dict:
        nonlocal role, type_name, awaiting_url
        endpoint: dict[str, Any] = {"product": product, "page": page, "title": title, "method": method, "url": url,
                                    "request_headers": [], "request": [], "response": [],
                                    "request_types": {}, "response_types": {}}
        endpoints.append(endpoint)
        role, type_name, awaiting_url = None, None, False
        return endpoint

    for block in blocks:
        if block[0] == "h":
            _, level, text = block
            heading = text.strip().rstrip(":").strip()
            if heading.upper() in HTTP_METHODS:
                neutral = prev_heading is not None and _role(prev_heading[1]) is None and prev_heading[0] <= 2
                cur = start(heading.upper(), None, prev_heading[1] if neutral and prev_heading else page_title)
                awaiting_url = True
            else:
                found = _role(heading)
                if found:
                    role, type_name = found, None
                elif role:
                    type_name = heading
            awaiting_url = awaiting_url and heading.upper() in HTTP_METHODS
            prev_heading = (level, heading)
            continue
        if block[0] == "t":
            text = block[1]
            base = _BASE_URL_RE.search(text)
            if base:
                base_url = base.group(1).rstrip("/.,;")
            line = _LINE_ENDPOINT_RE.search(text)
            if line:
                path = line.group(2).strip("`.,;")
                url = path if path.startswith("http") else ((base_url or "") + (path if path.startswith("/") else "/" + path))
                cur = start(line.group(1).upper(), url, page_title)
                continue
            line = _LINE_METHOD_RE.search(text)
            if line:
                path = line.group(2).strip("`.,;")
                cur = start(line.group(1).upper(), (base_url or "") + path if not path.startswith("http") else path, page_title)
                continue
            if awaiting_url and cur is not None:
                found_url = _URL_RE.search(text)
                if found_url:
                    cur["url"] = found_url.group(0).rstrip(".,;)")
                awaiting_url = False
            continue
        _, header, rows = block
        fields = _fields(header, rows)
        if fields is None or role is None:
            continue
        if cur is None:
            kept = role, type_name
            cur = start(None, None, page_title)
            role, type_name = kept
        if type_name is None:
            target = {"headers": "request_headers", "request": "request", "response": "response"}[role]
            cur[target] = sorted([*cur[target], *fields], key=lambda f: (f["name"], f["type"], str(f["required"])))
        else:
            types = cur["request_types" if role in ("request", "headers") else "response_types"]
            key, n = type_name, 2
            while key in types:
                key, n = f"{type_name} #{n}", n + 1
            types[key] = fields
    return endpoints


def endpoint_key(endpoint: dict) -> str:
    if endpoint["method"] and endpoint["url"]:
        return f"{endpoint['method']} {endpoint['url']}"
    return f"{endpoint['page']}#{endpoint['title']}"


def _doc_links(parser: _PageParser) -> list[str]:
    out = []
    for href in parser.hrefs:
        path = href.split("#", 1)[0]
        if re.fullmatch(r"/[a-z]+/api-reference/[^\s?]*\.html", path):
            out.append(path)
    return out


def collect_docs(fetch: Callable[[str], str]) -> dict:
    """The documentation snapshot: every page of the API reference of each product."""
    cache: dict[str, str] = {}

    def page_text(path: str) -> str:
        if path not in cache:
            cache[path] = fetch(DOCS_BASE + path)
        return cache[path]

    root = parse_page_loose(page_text("/"))
    seeds = sorted(set(_doc_links(root)))
    if not seeds:
        raise WatchError("documentation home page: no API reference links found; the site structure changed")
    pages: set[str] = set()
    for seed in seeds:
        product = seed.split("/")[1]
        parsed = parse_page_loose(page_text(seed))
        pages.add(seed)
        pages.update(p for p in _doc_links(parsed) if p.split("/")[1] == product)
    out_pages: dict[str, dict] = {}
    unavailable: list[str] = []
    for path in sorted(pages):
        try:
            parser = parse_page(page_text(path))
        except NotFound:
            parser = None
        if parser is None:
            unavailable.append(path)
            continue
        product = path.split("/")[1]
        endpoints = extract_endpoints(parser.blocks, product, path, parser.title)
        seen: dict[str, int] = {}
        for endpoint in endpoints:                     # a repeated key gets a suffix so nothing is lost
            key = endpoint_key(endpoint)
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > 1:
                endpoint["title"] = f"{endpoint['title']} #{seen[key]}"
        endpoints.sort(key=endpoint_key)
        out_pages[path] = {"title": parser.title, "endpoints": endpoints}
    total = sum(len(p["endpoints"]) for p in out_pages.values())
    if len(out_pages) < MIN_DOC_PAGES or total < MIN_DOC_ENDPOINTS:
        raise WatchError(f"documentation: only {len(out_pages)} pages and {total} endpoints recognized; "
                         "the site structure changed")
    return {"schema": SCHEMA, "source": DOCS_BASE, "pages": out_pages, "unavailable": sorted(unavailable)}


def parse_page_loose(html: str) -> _PageParser:
    parser = _PageParser()
    parser.feed(html)
    parser.close()
    return parser


# ======================================================================================== portal

_HASH_RE = re.compile(r"-[A-Za-z0-9_-]{8}$")
_FUNCTION_RE = re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")
_PATH_RE = re.compile(r"/api/v\d+/(?:[A-Za-z0-9_\-.]+|\$\{[^}]*\})(?:/(?:[A-Za-z0-9_\-.]+|\$\{[^}]*\}))*")
_CALL_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\(\s*([\"'`])(" + _PATH_RE.pattern + r")")
_CONFIG_CALL_RE = re.compile(r"url\s*:\s*([\"'`])(" + _PATH_RE.pattern + r")\1\s*,\s*method\s*:\s*([\"'])(\w+)\3")
_FETCH_RE = re.compile(r"(?<![\w$.])fetch\(\s*([\"'`])(?:https?://[\w.\-]+)?(" + _PATH_RE.pattern + r")\1\s*\)")
_IMPORT_RE = re.compile(r"import\s*\{([^}]*)\}\s*from\s*[\"']\./([^\"']+\.js)[\"']")
_EXPORT_RE = re.compile(r"export\s*\{([^}]*)\}(?!\s*from)")
_CHUNK_REF_RE = re.compile(r"[\"'](?:\./|/?assets/)([A-Za-z0-9_.\-]+\.js)[\"']")
_HEADER_RE = re.compile(r"[\"'](Simlessly-[A-Za-z]+)[\"']")
_CODES_RE = re.compile(r"\[((?:\s*[\"']\d{5}[\"']\s*,?)+)\]\s*\.includes\(")
_COOKIE_RE = re.compile(r"[\"'](simlessly_[a-z_]+)[\"']")
_NAV_CONTEXT_RE = re.compile(r"(?:window\.open\(|\.href\s*=)\s*[\"'`]?(?:https?://[\w.\-]+)?$")


def module_name(filename: str) -> str:
    """Chunk file name without its content hash: 'group-DIF3uJEs.js' -> 'group'."""
    return _HASH_RE.sub("", filename[:-3] if filename.endswith(".js") else filename)


def _function_body(js: str, open_brace: int, limit: int = 3000) -> str | None:
    """Text between the braces that start at js[open_brace], skipping string literals; None if not closed
    within `limit` characters."""
    depth, i, end = 0, open_brace, min(len(js), open_brace + limit)
    while i < end:
        c = js[i]
        if c in "\"'`":
            j = i + 1
            while j < end and js[j] != c:
                j += 2 if js[j] == "\\" else 1
            i = j
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return js[open_brace + 1:i]
        i += 1
    return None


def find_helpers(js: str) -> dict[str, str]:
    """Request helpers defined in this file, by what they do rather than by name (minified names change):
    sets `.params` -> 'query' (GET), sets `.data` -> 'json' (POST), builds a FormData and sets `.data`
    -> 'multipart' (POST). Wrappers that call a helper with a literal path are not helpers.

    Nested functions in bundled libraries can reuse a minified name. A name defined as helpers of different
    kinds is returned as 'ambiguous', and calls through it are not classified."""
    helpers: dict[str, str] = {}
    for match in _FUNCTION_RE.finditer(js):
        params = [p for p in match.group(2).split(",") if p.strip()]
        if len(params) < 2:
            continue
        body = _function_body(js, match.end() - 1)
        if body is None or "/api/" in body:
            continue
        sets_data = re.search(r"[\w$]\.data\s*=(?!=)", body) is not None
        sets_params = re.search(r"[\w$]\.params\s*=(?!=)", body) is not None
        if "FormData" in body and sets_data:
            kind = "multipart"
        elif sets_params and not sets_data:
            kind = "query"
        elif sets_data:
            kind = "json"
        else:
            continue
        name = match.group(1)
        helpers[name] = kind if helpers.get(name, kind) == kind else AMBIGUOUS
    return helpers


def _alias_list(text: str) -> list[tuple[str, str]]:
    """'a as b, c' -> [('a','b'), ('c','c')]; the pair is (name in the source module, name in the importer)."""
    out = []
    for item in text.split(","):
        parts = item.split()
        if len(parts) == 3 and parts[1] == "as":
            out.append((parts[0], parts[2]))
        elif len(parts) == 1:
            out.append((parts[0], parts[0]))
    return out


def _exports(js: str) -> dict[str, str]:
    """exported name -> local name"""
    out = {}
    for match in _EXPORT_RE.finditer(js):
        for local, exported in _alias_list(match.group(1)):
            out[exported] = local
    return out


AMBIGUOUS = "ambiguous"
_TRANSPORT_METHOD = {"query": "GET", "json": "POST", "multipart": "POST", "navigation": "GET", "fetch": "GET"}


def _normalize_path(path: str) -> str:
    return re.sub(r"\$\{[^}]*\}", "{}", path.split("?", 1)[0])


def scan_portal(fetch: Callable[[str], str]) -> dict:
    """The portal snapshot: every /api/ path the front-end calls, with method, transport and page module."""
    index = fetch(PORTAL_BASE + "/")
    entries = []
    for tag in re.findall(r"<script\b[^>]*>", index):
        if re.search(r"type\s*=\s*[\"']module[\"']", tag):
            src = re.search(r"src\s*=\s*[\"'](/assets/[^\"']+\.js)[\"']", tag)
            if src:
                entries.append(src.group(1).rsplit("/", 1)[1])
    if not entries:
        raise WatchError("portal index.html: no module script under /assets/ found; the site structure changed")
    files: dict[str, str] = {}
    queue = list(entries)
    while queue:
        name = queue.pop(0)
        if name in files:
            continue
        text = fetch(f"{PORTAL_BASE}/assets/{name}")
        if text.lstrip().lower().startswith("<!doctype") or "<html" in text[:200].lower():
            raise WatchError(f"{PORTAL_BASE}/assets/{name}: not a JavaScript file; the site structure changed")
        files[name] = text
        for ref in _CHUNK_REF_RE.findall(text):
            if ref not in files and ref not in queue:
                queue.append(ref)

    local_helpers = {name: find_helpers(text) for name, text in files.items()}
    if not any("query" in h.values() for h in local_helpers.values()) \
            or not any("json" in h.values() for h in local_helpers.values()):
        raise WatchError("portal: could not identify the GET (params) and POST (data) request helpers; "
                         "the site structure changed")
    exports = {name: _exports(text) for name, text in files.items()}

    # (method/transport pairs, modules) per path
    found: dict[str, dict] = {}

    def record(path: str, transport: str, module: str) -> None:
        entry = found.setdefault(path, {"transports": set(), "modules": set()})
        entry["transports"].add(transport)
        entry["modules"].add(module)

    for name, text in sorted(files.items()):
        module = module_name(name)
        kinds = dict(local_helpers[name])
        for imp in _IMPORT_RE.finditer(text):           # helpers imported from another chunk
            source = imp.group(2)
            for exported, local in _alias_list(imp.group(1)):
                src_local = exports.get(source, {}).get(exported)
                if src_local and src_local in local_helpers.get(source, {}):
                    imported = local_helpers[source][src_local]
                    kinds[local] = imported if kinds.get(local, imported) == imported else AMBIGUOUS
        claimed: set[int] = set()
        for call in _CALL_RE.finditer(text):
            claimed.add(call.start(3))
            kind = kinds.get(call.group(1))
            record(_normalize_path(call.group(3)), "unresolved" if kind in (None, AMBIGUOUS) else kind, module)
        for call in _CONFIG_CALL_RE.finditer(text):       # axios config object: {url: "...", method: "post", ...}
            claimed.add(call.start(2))
            method = call.group(4).lower()
            record(_normalize_path(call.group(2)), {"get": "query", "post": "json"}.get(method, "unresolved"), module)
        for call in _FETCH_RE.finditer(text):             # fetch("...") without options is a GET
            claimed.add(call.start(2))
            record(_normalize_path(call.group(2)), "fetch", module)
        for occurrence in _PATH_RE.finditer(text):
            if occurrence.start() in claimed:
                continue
            before = text[max(0, occurrence.start() - 80):occurrence.start()]
            record(_normalize_path(occurrence.group(0)),
                   "navigation" if _NAV_CONTEXT_RE.search(before) else "unresolved", module)

    if len(found) < MIN_PORTAL_PATHS:
        raise WatchError(f"portal: only {len(found)} /api/ paths recognized; the site structure changed")
    endpoints: dict[str, dict] = {}
    for path in sorted(found):
        transports = sorted(found[path]["transports"])
        if len(transports) == 1 and transports[0] != "unresolved":
            transport, method = transports[0], _TRANSPORT_METHOD[transports[0]]
        elif len(transports) == 1:
            transport, method = "unresolved", "UNKNOWN"
        else:
            transport, method = "|".join(transports), "CONFLICT"
        endpoints[path] = {"method": method, "transport": transport, "modules": sorted(found[path]["modules"])}
    unclassified = [p for p, e in endpoints.items() if e["method"] in ("UNKNOWN", "CONFLICT")]
    if len(unclassified) > len(endpoints) * MAX_UNCLASSIFIED_SHARE:
        raise WatchError(f"portal: the method of {len(unclassified)} of {len(endpoints)} /api/ paths could not be determined "
                         f"({', '.join(unclassified[:3])}{', ...' if len(unclassified) > 3 else ''}); the site structure changed")
    all_text = "\n".join(files[n] for n in sorted(files))
    codes = sorted({c for m in _CODES_RE.finditer(all_text) for c in re.findall(r"\d{5}", m.group(1))})
    return {"schema": SCHEMA, "source": PORTAL_BASE,
            "session_headers": sorted(set(_HEADER_RE.findall(all_text))),
            "session_cookies": sorted(set(_COOKIE_RE.findall(all_text))),
            "session_invalid_codes": codes,
            "endpoints": endpoints}


# ======================================================================================== snapshot files

def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load_snapshot(directory: Path) -> dict:
    """The portal snapshot (portal.json) in a directory."""
    try:
        return json.loads((directory / "portal.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise WatchError(f"cannot read the snapshot in {directory}: {err}") from None


def count_docs(docs: dict) -> int:
    return sum(len(p["endpoints"]) for p in docs["pages"].values())


def _resolved_docs(docs: dict) -> int:
    """Documentation endpoints that have both a method and a URL."""
    return sum(1 for p in docs["pages"].values() for e in p["endpoints"] if e["method"] and e["url"])


def _resolved_portal(portal: dict) -> int:
    return sum(1 for e in portal["endpoints"].values() if e["method"] in ("GET", "POST"))


def _page_counts(page: dict) -> tuple[int, int]:
    """(endpoints with method and URL, endpoints without) on one documentation page."""
    resolved = sum(1 for e in page["endpoints"] if e["method"] and e["url"])
    return resolved, len(page["endpoints"]) - resolved


def check_snapshot(portal: dict, baseline: dict | None, groups: dict) -> None:
    """Refuse a portal snapshot that is a failed or degraded reading of the site rather than an API change.
    Raises WatchError. `baseline` is the committed portal snapshot, if there is one."""
    for path, group in cli_portal_paths(groups).items():
        entry = portal["endpoints"].get(path)
        if entry and entry["method"] in ("UNKNOWN", "CONFLICT"):
            raise WatchError(f"portal path {path} ({group} group) used by the CLI could not be classified "
                             f"({entry['method']}, {entry['transport']}); refusing to write the snapshot")
    if baseline is None:
        return
    new_n, old_n = len(portal["endpoints"]), len(baseline["endpoints"])
    if old_n and new_n < old_n * SHRINK_LIMIT:
        raise WatchError(f"portal paths: {new_n} found, {old_n} in the committed snapshot; "
                         "refusing to write it (the scrape probably failed)")
    new_n, old_n = _resolved_portal(portal), _resolved_portal(baseline)
    if old_n and new_n < old_n * (1 - RESOLVED_DROP_LIMIT):
        raise WatchError(f"portal paths with a known method: {new_n} found, {old_n} in the committed snapshot; "
                         "refusing to write it (the site structure probably changed)")
    old_eps, new_eps = baseline["endpoints"], portal["endpoints"]
    flipped = [p for p in old_eps.keys() & new_eps.keys() if old_eps[p]["method"] != new_eps[p]["method"]]
    if len(flipped) > MAX_METHOD_CHANGES or (old_eps and len(flipped) > len(old_eps) * METHOD_CHANGE_SHARE):
        raise WatchError(f"portal: the method of {len(flipped)} of {len(old_eps)} paths changed at once "
                         f"({', '.join(sorted(flipped)[:3])}, ...); that is more likely a misreading of the front-end "
                         "than an API change. Refusing to write the snapshot (use --force after checking by hand)")


def check_docs(docs: dict, old_docs: dict, rsp_paths: set[str]) -> None:
    """Refuse a documentation reading that is a failed or degraded scrape rather than a change of the documentation."""
    new_n, old_n = count_docs(docs), count_docs(old_docs)
    if old_n and new_n < old_n * SHRINK_LIMIT:
        raise WatchError(f"documentation endpoints: {new_n} found, {old_n} in the stored snapshot; "
                         "refusing to use it (the scrape probably failed)")
    new_n, old_n = _resolved_docs(docs), _resolved_docs(old_docs)
    if old_n and new_n < old_n * (1 - RESOLVED_DROP_LIMIT):
        raise WatchError(f"documentation endpoints with a method and URL: {new_n} found, {old_n} in the stored snapshot; "
                         "refusing to use it (the site structure probably changed)")
    for path in sorted(rsp_paths):                       # a CLI call whose documentation page is still there but unreadable
        for page_path, page in old_docs["pages"].items():
            if not any(_url_path(e["url"]) == path for e in page["endpoints"]) or page_path not in docs["pages"]:
                continue
            old_resolved, old_open = _page_counts(page)
            new_resolved, new_open = _page_counts(docs["pages"][page_path])
            if new_resolved < old_resolved and new_open > old_open:
                raise WatchError(f"documentation page {page_path} (documents {path}, which the CLI calls) lost the method "
                                 "or URL of an endpoint; refusing to use it (--force skips this check)")


def keep_known_modules(portal: dict, old_portal: dict) -> None:
    """The page modules of a path are context only (front-end chunk names move with every rebuild). A path whose
    method and transport did not change keeps the committed modules, so a rebuild alone changes no file."""
    for path, entry in portal["endpoints"].items():
        old = old_portal["endpoints"].get(path)
        if old and (old["method"], old["transport"]) == (entry["method"], entry["transport"]):
            entry["modules"] = old["modules"]


def cmd_snapshot(args: argparse.Namespace, fetch: Callable[[str], str] | None = None) -> int:
    fetch = fetch or Fetcher()
    portal = scan_portal(fetch)
    baseline_file = Path(args.baseline) / "portal.json"
    baseline = load_snapshot(Path(args.baseline)) if baseline_file.exists() else None
    if not args.force:
        check_snapshot(portal, baseline, load_endpoint_groups(Path(args.endpoints)))
    if baseline:
        keep_known_modules(portal, baseline)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "portal.json").write_text(dump_json(portal), encoding="utf-8")
    print(f"snapshot written to {out}: {len(portal['endpoints'])} portal paths")
    return 0


# ======================================================================================== diff

def _code(text: Any) -> str:
    """Scraped text as an inline code span: no markup, mentions or line breaks reach the report."""
    s = _clean(str(text)).replace("`", "'")
    return "`" + (s[:200] + "..." if len(s) > 200 else s) + "`"


def _field_text(f: dict) -> str:
    req = {True: "required", False: "optional", None: "requirement not stated"}.get(f["required"], f["required"])
    return f"{f['name']} ({f['type'] or 'no type'}, {req})"


def _diff_fields(label: str, old: list[dict], new: list[dict]) -> list[str]:
    o, n = {f["name"]: f for f in old}, {f["name"]: f for f in new}
    out = []
    for name in sorted(n.keys() - o.keys()):
        out.append(f"{label}: added field {_code(_field_text(n[name]))}")
    for name in sorted(o.keys() - n.keys()):
        out.append(f"{label}: removed field {_code(_field_text(o[name]))}")
    for name in sorted(o.keys() & n.keys()):
        if o[name] != n[name]:
            out.append(f"{label}: field {_code(name)} changed from {_code(_field_text(o[name]))} to {_code(_field_text(n[name]))}")
    return out


def diff_endpoint(old: dict, new: dict) -> list[str]:
    out = []
    for key in ("title", "method", "url", "page"):
        if old[key] != new[key]:
            out.append(f"{key} changed from {_code(old[key])} to {_code(new[key])}")
    for key, label in (("request_headers", "request headers"), ("request", "request"), ("response", "response")):
        out += _diff_fields(label, old[key], new[key])
    for key, label in (("request_types", "request type"), ("response_types", "response type")):
        for name in sorted(old[key].keys() | new[key].keys()):
            if name not in old[key]:
                out.append(f"{label} {_code(name)} added")
            elif name not in new[key]:
                out.append(f"{label} {_code(name)} removed")
            else:
                out += _diff_fields(f"{label} {_code(name)}", old[key][name], new[key][name])
    return out


def _docs_endpoints(docs: dict) -> dict[str, dict]:
    out = {}
    for page in docs["pages"].values():
        for endpoint in page["endpoints"]:
            out[endpoint_key(endpoint)] = endpoint
    return out


def diff_docs(old: dict, new: dict) -> dict:
    o, n = _docs_endpoints(old), _docs_endpoints(new)
    return {"added": sorted(n.keys() - o.keys()), "removed": sorted(o.keys() - n.keys()),
            "changed": {k: diff_endpoint(o[k], n[k]) for k in sorted(o.keys() & n.keys()) if o[k] != n[k]},
            "pages_added": sorted(new["pages"].keys() - old["pages"].keys()),
            "pages_removed": sorted(old["pages"].keys() - new["pages"].keys()),
            "unavailable_added": sorted(set(new["unavailable"]) - set(old["unavailable"])),
            "unavailable_removed": sorted(set(old["unavailable"]) - set(new["unavailable"])),
            "old_endpoints": o, "new_endpoints": n}


def same_portal(old: dict, new: dict) -> bool:
    """Equal apart from the page modules, which are context and not part of the API."""
    def core(portal: dict) -> dict:
        return {**portal, "endpoints": {p: {k: v for k, v in e.items() if k != "modules"} for p, e in portal["endpoints"].items()}}
    return core(old) == core(new)


def diff_portal(old: dict, new: dict) -> dict:
    o, n = old["endpoints"], new["endpoints"]
    changed = {}
    for path in sorted(o.keys() & n.keys()):
        notes = []
        if o[path]["method"] != n[path]["method"]:
            notes.append(f"method changed from {o[path]['method']} to {n[path]['method']}")
        if o[path]["transport"] != n[path]["transport"]:
            notes.append(f"transport changed from {o[path]['transport']} to {n[path]['transport']}")
        if notes:
            changed[path] = notes
    other = []
    for key, label in (("session_headers", "session headers"), ("session_cookies", "session cookies"),
                       ("session_invalid_codes", "session-invalid codes")):
        if old.get(key) != new.get(key):
            other.append(f"{label} changed from {_code(', '.join(old.get(key, [])) or 'none')} to {_code(', '.join(new.get(key, [])) or 'none')}")
    return {"added": sorted(n.keys() - o.keys()), "removed": sorted(o.keys() - n.keys()), "changed": changed,
            "other": other, "old": o, "new": n}


def cli_rsp_paths() -> set[str]:
    """Paths the CLI's RSP client calls (client.ALLOWED_PATHS)."""
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from simlessly_cli import client
        return set(client.ALLOWED_PATHS)
    finally:
        sys.path.pop(0)


def load_endpoint_groups(path: Path = ENDPOINTS_FILE) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in ("session", "read", "write", "multipart"):
            data[key]
        return data
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise WatchError(f"cannot read {path}: {err}") from None


def cli_portal_paths(groups: dict) -> dict[str, str]:
    """allowlisted path -> group"""
    return {path: group for group in ("session", "read", "write") for path in groups[group]}


def _url_path(url: str | None) -> str:
    return urlsplit(url).path if url else ""


def plan_apply(groups: dict, new_portal: dict) -> dict:
    """What `apply` would do for the CLI's allowlisted portal paths, without changing anything."""
    applied, skipped, missing = [], [], []
    multipart = set(groups["multipart"])
    for path, group in cli_portal_paths(groups).items():
        current = groups[group][path]
        entry = new_portal["endpoints"].get(path)
        if entry is None:
            missing.append(path)
            continue
        method, transport = entry["method"], entry["transport"]
        is_multipart = path in multipart
        transport_ok = transport == "multipart" if is_multipart else transport in ("json", "query")
        if method == current and transport_ok:
            continue
        if method not in ("GET", "POST"):
            skipped.append((path, f"the portal front-end now calls it in a way this tool cannot classify ({method}, {transport})"))
        elif not transport_ok:
            skipped.append((path, "the way the portal sends the request changed "
                                  f"({'file upload' if is_multipart else 'JSON or query string'} in the CLI, {transport} in the portal)"))
        elif group != "read":
            skipped.append((path, f"its method changed from {current} to {method} in the {group} group, which is only changed by hand"))
        else:
            applied.append((group, path, current, method))
    return {"applied": applied, "skipped": skipped, "missing": missing}


def _portal_section(portal: dict, allow: dict[str, str]) -> list[str]:
    total = len(portal["added"]) + len(portal["removed"]) + len(portal["changed"]) + len(portal["other"])
    lines = ["## Portal", ""]
    if total == 0:
        lines += ["No changes.", ""]
    if portal["changed"]:
        lines += ["### Changed paths", ""]
        for path, notes in portal["changed"].items():
            used = " (used by the CLI)" if path in allow else ""
            lines.append(f"- {_code(path)}{used}: " + "; ".join(notes))
        lines.append("")
    if portal["added"]:
        lines += ["### New paths (not added to the CLI)", ""]
        for path in portal["added"]:
            e = portal["new"][path]
            lines.append(f"- {_code(e['method'] + ' ' + path)} in " + ", ".join(_code(m) for m in e["modules"]))
        lines.append("")
    if portal["removed"]:
        lines += ["### Removed paths", ""]
        for path in portal["removed"]:
            used = " (used by the CLI)" if path in allow else ""
            lines.append(f"- {_code(portal['old'][path]['method'] + ' ' + path)}{used}")
        lines.append("")
    if portal["other"]:
        lines += ["### Session details", ""] + [f"- {t}" for t in portal["other"]] + [""]
    return lines


def build_report(old_portal: dict, new_portal: dict, groups: dict) -> str:
    """The Markdown report of a portal change (the weekly job's pull request text)."""
    portal = diff_portal(old_portal, new_portal)
    allow = cli_portal_paths(groups)
    plan = plan_apply(groups, new_portal)

    lines = ["# API change report", ""]
    if same_portal(old_portal, new_portal):
        lines += ["No changes since the committed snapshot.", ""]
        return "\n".join(lines)
    lines += ["## Summary", "",
              f"- Portal: {len(portal['added'])} paths added, {len(portal['removed'])} removed, "
              f"{len(portal['changed'])} changed.", ""]

    manual: list[str] = []
    for path in portal["removed"]:
        if path in allow:
            manual.append(f"Portal path {_code(path)} ({allow[path]} group) is no longer called by the portal front-end. "
                          "Check whether the command that uses it still works.")
    for path, reason in plan["skipped"]:
        manual.append(f"Portal path {_code(path)} changed, not applied: {reason}.")
    for path in plan["missing"]:
        if path not in portal["removed"]:
            manual.append(f"Portal path {_code(path)} is not in the new snapshot.")
    if manual:
        lines += ["## Needs manual follow-up", ""] + [f"- {m}" for m in manual] + [""]
    return "\n".join(lines + _portal_section(portal, allow))


def build_docs_report(old_docs: dict, new_docs: dict, rsp_paths: set[str]) -> str:
    """The Markdown report of a documentation change (printed on the customer's machine by docs-check)."""
    docs = diff_docs(old_docs, new_docs)
    docs_total = len(docs["added"]) + len(docs["removed"]) + len(docs["changed"]) + len(docs["pages_added"]) \
        + len(docs["pages_removed"]) + len(docs["unavailable_added"]) + len(docs["unavailable_removed"])
    lines = ["# Documentation change report", ""]
    if old_docs == new_docs:
        lines += ["No changes since the stored snapshot.", ""]
        return "\n".join(lines)
    lines += ["## Summary", "",
              f"- Documentation: {len(docs['added'])} endpoints added, {len(docs['removed'])} removed, "
              f"{len(docs['changed'])} changed.", ""]

    manual: list[str] = []
    for key in docs["removed"]:
        if _url_path(docs["old_endpoints"][key]["url"]) in rsp_paths:
            manual.append(f"Documentation for {_code(key)}, which the CLI calls, was removed.")
    for key, notes in docs["changed"].items():
        if _url_path(docs["new_endpoints"][key]["url"]) in rsp_paths:
            manual.append(f"Documentation for {_code(key)}, which the CLI calls, changed: " + "; ".join(notes[:6])
                          + (f"; and {len(notes) - 6} more" if len(notes) > 6 else "") + ".")
    if manual:
        lines += ["## Needs manual follow-up", ""] + [f"- {m}" for m in manual] + [""]

    lines += ["## Documentation", ""]
    if docs_total == 0:
        lines += ["No changes.", ""]
    if docs["added"]:
        lines += ["### New endpoints", ""]
        for key in docs["added"]:
            e = docs["new_endpoints"][key]
            lines.append(f"- {_code(key)} ({e['product']}, {_code(e['title'])}), page {_code(e['page'])}")
        lines.append("")
    if docs["removed"]:
        lines += ["### Removed endpoints", ""]
        for key in docs["removed"]:
            e = docs["old_endpoints"][key]
            lines.append(f"- {_code(key)} ({e['product']}, {_code(e['title'])}), page {_code(e['page'])}")
        lines.append("")
    if docs["changed"]:
        lines += ["### Changed endpoints", ""]
        for key, notes in docs["changed"].items():
            lines.append(f"- {_code(key)}")
            lines += [f"  - {n}" for n in notes]
        lines.append("")
    if docs["pages_added"] or docs["pages_removed"]:
        lines += ["### Pages", ""]
        lines += [f"- added {_code(p)}" for p in docs["pages_added"]]
        lines += [f"- removed {_code(p)}" for p in docs["pages_removed"]]
        lines.append("")
    if docs["unavailable_added"] or docs["unavailable_removed"]:
        lines += ["### Linked pages that do not exist", ""]
        lines += [f"- now missing {_code(p)}" for p in docs["unavailable_added"]]
        lines += [f"- now available {_code(p)}" for p in docs["unavailable_removed"]]
        lines.append("")
    return "\n".join(lines)


def cap_report(text: str, full_data: str = "The snapshot files in `api-snapshot/` have the full data.") -> str:
    if len(text) <= REPORT_LIMIT:
        return text
    return text[:REPORT_LIMIT].rsplit("\n", 1)[0] + f"\n\n(Report shortened. {full_data})\n"


def cmd_diff(args: argparse.Namespace, fetch: Callable[[str], str] | None = None) -> int:
    old_portal = load_snapshot(Path(args.old))
    if args.new:
        new_portal = load_snapshot(Path(args.new))
    else:
        new_portal = scan_portal(fetch or Fetcher())
    report = cap_report(build_report(old_portal, new_portal, load_endpoint_groups()))
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    print("snapshot differs from the committed one" if not same_portal(old_portal, new_portal) else "no changes",
          file=sys.stderr)
    return 0


# ======================================================================================== apply

def apply_methods(groups: dict, new_portal: dict) -> tuple[dict, dict]:
    """(updated groups, plan). Only the method of a path that is already in the read group can change."""
    plan = plan_apply(groups, new_portal)
    updated = {k: (dict(v) if isinstance(v, dict) else list(v)) for k, v in groups.items()}
    for group, path, _old, new in plan["applied"]:
        updated[group][path] = new
    return updated, plan


def apply_section(plan: dict) -> str:
    lines = ["## Applied automatically", ""]
    if plan["applied"]:
        lines.append("HTTP methods updated in `src/simlessly_cli/portal_endpoints.json`:")
        lines.append("")
        lines += [f"- {_code(path)} ({group}): {old} to {new}" for group, path, old, new in plan["applied"]]
        lines += ["", "The commands that use these paths still build their request for the previous method (JSON body "
                      "or query string), so the unit tests can fail until the request is adapted by hand."]
    else:
        lines.append("No code changes.")
    lines.append("")
    return "\n".join(lines)


def cmd_apply(args: argparse.Namespace) -> int:
    endpoints_file = Path(args.endpoints)
    groups = load_endpoint_groups(endpoints_file)
    new_portal = load_snapshot(Path(args.new))
    updated, plan = apply_methods(groups, new_portal)
    if updated != groups:
        endpoints_file.write_text(json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.report:
        with open(args.report, "a", encoding="utf-8") as fh:
            fh.write("\n" + apply_section(plan))
    for group, path, old, new in plan["applied"]:
        print(f"{path}: {old} -> {new}")
    print(f"{len(plan['applied'])} method(s) updated, {len(plan['skipped'])} not applied, {len(plan['missing'])} missing")
    return 0


# ======================================================================================== docs-check (local, signed in)

# A cookie value as RFC 6265 allows it: printable ASCII without space, quote, comma, semicolon and backslash.
_COOKIE_VALUE_RE = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]+")


def _cli_modules() -> tuple[Any, Any, Any, Any, Any]:
    """The CLI's own modules: settings, secret stores, portal client, output redaction."""
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from simlessly_cli import client, config, output, portal, store
        return client, config, output, portal, store
    finally:
        sys.path.pop(0)


def docs_snapshot_path(env: Any) -> tuple[Path, bool]:
    """(path of the private documentation snapshot, whether it is in the default config directory).
    $SIMLESSLY_DOCS_SNAPSHOT, else $XDG_CONFIG_HOME/simlessly-cli/docs-snapshot.json, else
    ~/.config/simlessly-cli/docs-snapshot.json (the directory of the credentials file)."""
    explicit = (env.get(DOCS_SNAPSHOT_ENV) or "").strip()
    if explicit:
        return Path(explicit).expanduser(), False
    xdg = (env.get("XDG_CONFIG_HOME") or "").strip()
    try:
        base = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".config"
    except RuntimeError:
        raise WatchError(f"no home directory, so there is no default snapshot location; set {DOCS_SNAPSHOT_ENV}") from None
    return base / CONFIG_DIR_NAME / DOCS_SNAPSHOT_FILE, True


def work_tree_of(path: Path) -> Path | None:
    """The git work tree (or this repository) that contains `path`, once symbolic links are resolved; else None."""
    real = Path(os.path.realpath(path))
    for directory in (real, *real.parents):
        if directory == ROOT or (directory / ".git").exists():
            return directory
    return None


def private_target(path: Path, what: str) -> Path:
    """The resolved location for a file that holds documentation content. Refuses a path inside a git work tree."""
    tree = work_tree_of(path)
    if tree is not None:
        raise WatchError(f"refusing to write the {what} to {path}: it is inside the git work tree {tree}. The documentation "
                         f"is for signed-in customers and must not be committed. Use a path outside any repository"
                         + (f" ({DOCS_SNAPSHOT_ENV} sets the snapshot location)" if what == "snapshot" else ""))
    return Path(os.path.realpath(path))


def write_private_file(target: Path, text: str, *, make_dirs: bool, tighten_dir: bool = False) -> None:
    """Atomic write of a file readable by the owner only. New directories are created with mode 0700."""
    posix = os.name == "posix"
    parent = target.parent
    try:
        if make_dirs:
            missing = []
            directory = parent
            while not directory.exists():
                missing.append(directory)
                directory = directory.parent
            for directory in reversed(missing):
                directory.mkdir(mode=0o700)
                if posix:
                    os.chmod(directory, 0o700)
            if posix and not missing and parent.stat().st_mode & 0o077:
                if tighten_dir:
                    os.chmod(parent, 0o700)
                else:
                    print(f"api_watch: warning: {parent} can be read by other users", file=sys.stderr)
        fd, tmp_name = tempfile.mkstemp(prefix=".docs-", dir=str(parent))
    except OSError as err:
        raise WatchError(f"could not write {target}: {err.strerror or type(err).__name__}") from None
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            if posix:
                os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except OSError as err:
        raise WatchError(f"could not write {target}: {err.strerror or type(err).__name__}") from None
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def load_docs_snapshot(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise WatchError(f"cannot read the stored documentation snapshot {path}: {err}. "
                         "Delete it, or run docs-check --update --force") from None
    if not (isinstance(data, dict) and data.get("schema") == SCHEMA and isinstance(data.get("pages"), dict)
            and isinstance(data.get("unavailable"), list)):
        raise WatchError(f"{path} is not a documentation snapshot this version can read. "
                         "Delete it, or run docs-check --update --force")
    return data


def signed_in_token(env: Any) -> tuple[str, Any]:
    """The stored portal session token, checked the way the documentation site checks it. Returns (token, redactor).

    The token comes from the CLI's settings in the CLI's order (environment, OS secret store, credentials file).
    Raises WatchError, with "sign in first" in the message, when there is none or the portal does not accept it."""
    client, config, output, portal, store = _cli_modules()
    settings = config.Settings(env, config.keychain_lookup, file_store=store.CredentialsFile.for_env(env),
                               keychain_source=store.os_store_name() or "keychain")
    try:
        token = settings.get("portal-token").value
        base_url = settings.base_url()
    except config.ConfigError as err:
        raise WatchError(str(err)) from None
    if not token:
        raise WatchError(f"no portal session is stored; {SIGN_IN_FIRST}")
    redactor = output.Redactor()
    redactor.add(token)
    if not _COOKIE_VALUE_RE.fullmatch(token):
        raise WatchError(f"the stored portal token contains characters that cannot be sent; {SIGN_IN_FIRST}")
    session = portal.PortalClient(base_url, token, timezone=portal.local_timezone({"TZ": settings.env_value("TZ") or ""}),
                                  redactor=redactor)
    try:
        session.read(portal.PATH_PLAN_QUERY_ORDER, {})
    except portal.PortalSessionExpired:
        raise WatchError(f"the stored portal session is expired or invalid; {SIGN_IN_FIRST}") from None
    except client.SimlesslyError as err:
        raise WatchError("could not check the portal session: " + redactor.scrub(str(err))) from None
    return token, redactor


def cmd_docs_check(args: argparse.Namespace, fetch_factory: Callable[[str], Callable[[str], str]] | None = None) -> int:
    env = os.environ
    path, default_dir = docs_snapshot_path(env)
    target = private_target(path, "snapshot")
    report_target = private_target(Path(args.report), "report") if args.report else None
    token, redactor = signed_in_token(env)
    fetch = fetch_factory(token) if fetch_factory else Fetcher(session_token=token)
    try:
        docs = collect_docs(fetch)
    except WatchError as err:
        raise WatchError(redactor.scrub(str(err))) from None
    old = None
    if target.exists() and not (args.update and args.force):
        old = load_docs_snapshot(target)
    try:
        if old is not None and not args.force:
            check_docs(docs, old, cli_rsp_paths())
        if args.update:
            if old is not None and old != docs:
                d = diff_docs(old, docs)
                changes = (f"; since the previous one: {len(d['added'])} endpoints added, {len(d['removed'])} removed, "
                           f"{len(d['changed'])} changed")
            else:
                changes = ""
            write_private_file(target, dump_json(docs), make_dirs=True, tighten_dir=default_dir)
            print(f"documentation snapshot written to {target}: {len(docs['pages'])} pages, {count_docs(docs)} endpoints"
                  + changes)
            return 0
        if old is None:
            raise WatchError(f"no documentation snapshot at {target} yet; run docs-check --update to create it")
        report = cap_report(build_docs_report(old, docs, cli_rsp_paths()), "The stored snapshot has the full data.")
    except (KeyError, TypeError, AttributeError):
        raise WatchError(f"the stored documentation snapshot {target} has an unexpected structure. "
                         "Delete it, or run docs-check --update --force") from None
    if report_target:
        write_private_file(report_target, report, make_dirs=False)
    else:
        sys.stdout.write(report)
    changed = old != docs
    print("documentation differs from the stored snapshot" if changed else "no changes", file=sys.stderr)
    return 1 if changed else 0


# ======================================================================================== main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="api_watch.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("snapshot", help="fetch the portal's front-end files and write portal.json")
    p.add_argument("--out", default=str(SNAPSHOT_DIR), help="output directory (default: api-snapshot)")
    p.add_argument("--baseline", default=str(SNAPSHOT_DIR), help="committed snapshot used to detect a failed scrape")
    p.add_argument("--endpoints", default=str(ENDPOINTS_FILE), help="the CLI's portal endpoint data file")
    p.add_argument("--force", action="store_true", help="write even if the sanity checks against the baseline fail")
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("diff", help="compare a new snapshot with the committed one and write a Markdown report")
    p.add_argument("--old", default=str(SNAPSHOT_DIR), help="committed snapshot directory (default: api-snapshot)")
    p.add_argument("--new", help="new snapshot directory; without it the live portal is fetched")
    p.add_argument("--report", help="write the report to this file instead of stdout")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("apply", help="update methods of read-group portal paths from a snapshot")
    p.add_argument("--new", default=str(SNAPSHOT_DIR), help="snapshot directory with portal.json (default: api-snapshot)")
    p.add_argument("--endpoints", default=str(ENDPOINTS_FILE), help="the CLI's portal endpoint data file")
    p.add_argument("--report", help="append an 'Applied automatically' section to this report")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("docs-check", help="compare the API documentation with a private snapshot (needs a portal session)",
                       description="Check the stored portal session, fetch the API documentation and compare it with the "
                                   f"private snapshot (default ~/.config/simlessly-cli/{DOCS_SNAPSHOT_FILE}, or "
                                   f"${DOCS_SNAPSHOT_ENV}). Exit 0: no changes. Exit 1: changes, or a refusal or error.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--update", action="store_true", help="write the private snapshot instead of printing a report")
    mode.add_argument("--report", help="write the change report to this file (outside any git work tree) instead of stdout")
    p.add_argument("--force", action="store_true", help="skip the sanity checks against the stored snapshot")
    p.set_defaults(func=cmd_docs_check)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except WatchError as err:
        print(f"api_watch: error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
