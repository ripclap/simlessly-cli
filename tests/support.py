"""Shared test helpers: a local mock Simlessly server and a CLI runner.

The mock verifies each request's signature with its own implementation (separate from
simlessly_cli.auth), so a signing mistake fails every test that makes a call. A network guard
stops any test from reaching a non-loopback host.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
import atexit
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from simlessly_cli.cli import main  # noqa: E402

# ---- network guard: loopback only ------------------------------------------------
_LOOPBACK = {"127.0.0.1", "localhost", "::1", None, ""}
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect


def _guarded_getaddrinfo(host, *a, **k):
    if host not in _LOOPBACK:
        raise OSError(f"tests may not resolve non-loopback host {host!r}")
    return _real_getaddrinfo(host, *a, **k)


def _guarded_connect(self, address):
    if isinstance(address, tuple) and address and address[0] not in _LOOPBACK:
        raise OSError(f"tests may not connect to {address[0]!r}")
    return _real_connect(self, address)


socket.getaddrinfo = _guarded_getaddrinfo
socket.socket.connect = _guarded_connect

# ---- isolation: never touch the real home, credentials file or secret stores ----------
_TEST_HOME = tempfile.mkdtemp(prefix="simlessly-test-home-")
atexit.register(shutil.rmtree, _TEST_HOME, ignore_errors=True)
for _var in ("HOME", "USERPROFILE"):
    os.environ[_var] = _TEST_HOME
for _var in [v for v in os.environ if v.startswith("SIMLESSLY_")] + ["XDG_CONFIG_HOME"]:
    os.environ.pop(_var, None)

_real_subprocess_run = subprocess.run
_FORBIDDEN_TOOLS = {"security", "secret-tool"}


def _guarded_run(cmd, *a, **k):
    if isinstance(cmd, (list, tuple)) and cmd and os.path.basename(str(cmd[0])) in _FORBIDDEN_TOOLS:
        raise AssertionError(f"tests may not run the real {cmd[0]!r}; mock subprocess.run")
    return _real_subprocess_run(cmd, *a, **k)


subprocess.run = _guarded_run

# ---- fabricated values -----------------------------------------------------------
ACCESS = "TESTACCESS-key-456"
SECRET = "TESTSECRET-do-not-leak-123"
KI = "0123456789ABCDEF0123456789ABCDEF"
OPC = "FEDCBA9876543210FEDCBA9876543210"
ICCID = "8999000000000000001"
IMSI = "001010000000001"
EID = "89049032000000000000000000000001"
AC = "1$rsp-eu.simlessly.com$ABCDEF0123456789ABCDEF0123456789"
AC_LINK = "https://static.simlessly.com/qr/abc123-secretlink.png"
CONFIG = "demo-config"
ENV = {"SIMLESSLY_ACCESS_KEY": ACCESS, "SIMLESSLY_SECRET_KEY": SECRET, "SIMLESSLY_NO_KEYCHAIN": "1",
       "SIMLESSLY_NO_CREDENTIALS_FILE": "1"}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def envelope(obj, success=True, msg="ok", code="00000"):
    return {"obj": obj, "success": success, "msg": msg, "code": code}


def ok(obj):
    return 200, envelope(obj), {}


@dataclass
class Record:
    path: str
    headers: dict
    body: str
    problems: list = field(default_factory=list)
    method: str = "POST"
    query: str = ""            # the raw query string of a GET (no leading '?')
    raw: bytes = b""           # the request body as received


class MockSimlessly:
    """Routes: path -> callable(Record) -> (status, payload, extra_headers) or a dict with 'delay'."""

    # path -> the only HTTP method accepted there (None: no check). MockPortal sets it.
    METHODS: dict | None = None

    def __init__(self) -> None:
        self.routes: dict = {}
        self.requests: list[Record] = []
        self._seen_ids: set[str] = set()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def do_POST(self):  # noqa: N802
                self._serve("POST")

            def do_GET(self):  # noqa: N802
                self._serve("GET")

            def _serve(self, method):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                path, _, query = self.path.partition("?")
                rec = Record(path, {k: v for k, v in self.headers.items()}, raw.decode("utf-8", "replace"), method=method,
                             query=query, raw=raw)
                rec.problems = outer.verify(rec)
                outer.requests.append(rec)
                allowed = (outer.METHODS or {}).get(path)
                if allowed is not None and allowed != method:
                    # What the live portal does: HTTP 200 with a failure envelope and code 10008.
                    status, payload, extra = 200, envelope(
                        None, False, f"request method not support[Request method '{method}' not supported]", "10008"), {}
                elif rec.problems:
                    status, payload, extra = 401, envelope(None, False, "bad signature: " + "; ".join(rec.problems), "E401"), {}
                elif path in outer.routes:
                    result = outer.routes[path](rec)
                    if len(result) == 4:
                        time.sleep(result[3])
                    status, payload, extra = result[:3]
                else:
                    status, payload, extra = 404, envelope(None, False, "no route", "E404"), {}
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(data)
                except OSError:
                    pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):  # client hung up (timeout tests)
                pass

        self.httpd = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()

    def verify(self, rec: Record) -> list[str]:
        """The spec, restated: headers, ms timestamp inside 10 min, unused RequestID, UPPERCASE HMAC."""
        h, problems = rec.headers, []
        for name in ("AccessKey", "Timestamp", "RequestID", "Signature"):
            if name not in h:
                problems.append(f"missing {name}")
        if problems:
            return problems
        if h["AccessKey"] != ACCESS:
            problems.append("AccessKey mismatch")
        if not re.fullmatch(r"\d{13}", h["Timestamp"]) or abs(time.time() * 1000 - int(h["Timestamp"])) > 600_000:
            problems.append("Timestamp not 13-digit ms within 10 minutes")
        if not UUID_RE.match(h["RequestID"]):
            problems.append("RequestID not a UUID v4")
        if h["RequestID"] in self._seen_ids:
            problems.append("RequestID reused")
        self._seen_ids.add(h["RequestID"])
        expected = hmac.new(SECRET.encode(), (h["Timestamp"] + h["RequestID"] + h["AccessKey"] + rec.body).encode(),
                            hashlib.sha256).hexdigest().upper()
        if h["Signature"] != expected:
            problems.append("Signature mismatch")
        if h.get("Content-Type") != "application/json":
            problems.append("Content-Type")
        return problems

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.server = MockSimlessly()
        self.addCleanup(self.server.close)
        self.env = {**ENV, "SIMLESSLY_BASE_URL": self.server.url}

    def run_cli(self, *argv, env=None, keychain=None, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        code = main(list(argv), env=self.env if env is None else env, keychain=keychain,
                    stdout=out, stderr=err, stdin=stdin or io.StringIO())
        return code, out.getvalue(), err.getvalue()

    def assertNoSecrets(self, *texts, extra=()):
        for text in texts:
            for secret in (ACCESS, SECRET, KI, OPC, *extra):
                self.assertNotIn(secret, text)

    def assertAllSigned(self):
        for rec in self.server.requests:
            self.assertEqual(rec.problems, [], rec.path)


class MockPortal(MockSimlessly):
    """A local stand-in for the portal's session API: a session token, no signature.

    Routes as in MockSimlessly. verify() checks Content-Type, a 13-digit ms Simlessly-Timestamp, a
    fresh uuid4 Simlessly-RequestID, an IANA Simlessly-TimeZone and no AccessKey or Signature headers.
    Each route decides whether the token is acceptable (the real portal answers HTTP 200 with code 10102).
    """

    # Defined separately from simlessly_cli.portal: the HTTP method per path.
    METHODS = {
        # session
        "/api/v1/user/login": "POST", "/api/v1/user/logout": "GET",
        # read-only
        "/api/v1/fleet/list": "POST", "/api/v1/fleet/recycle/query": "POST", "/api/v1/fleet/transaction": "POST",
        "/api/v1/fleet/qrcode": "POST", "/api/v1/log/profile/list": "POST", "/api/v1/log/profile/detail": "GET",
        "/api/v1/log/batch-task/list": "POST", "/api/v1/log/recycle/list": "POST",
        "/api/v1/config/name/query": "GET", "/api/v1/config/query": "POST", "/api/v1/config/detail": "GET",
        "/api/v1/group/list": "POST", "/api/v1/campaign/list": "GET", "/api/v1/campaign/resource/list": "POST",
        "/api/v1/block/list": "POST", "/api/v1/event/profile/query": "GET",
        "/api/v1/analytic/percentage": "GET", "/api/v1/analytic/deviceBrand": "GET",
        "/api/v1/analytic/profileStatus": "GET", "/api/v1/analytic/downloadByDay": "POST",
        "/api/v1/analytic/downloadByMonth": "POST", "/api/v1/analytic/redownload": "POST",
        "/api/v1/analytic/ac-count": "GET", "/api/v1/analytic/latest-week": "GET",
        "/api/v1/report/config/query": "POST", "/api/v1/plan/queryOrder": "POST", "/api/v1/plan/list": "POST",
        "/api/v1/order/list": "POST", "/api/v1/order/detail": "POST", "/api/v1/enterprise/info": "GET",
        "/api/v1/enterprise/list": "GET", "/api/v1/enum/list": "POST",
        # state-changing
        "/api/v1/fleet/delete": "POST", "/api/v1/fleet/update-notes": "POST", "/api/v1/fleet/re-generate": "POST",
        "/api/v1/fleet/recycle": "POST", "/api/v1/fleet/generateAc": "POST", "/api/v1/group/add": "POST",
        "/api/v1/group/batchGroup": "POST",
    }

    def verify(self, rec: Record) -> list[str]:
        h, problems = rec.headers, []
        for name in ("Simlessly-Timestamp", "Simlessly-RequestID", "Simlessly-TimeZone"):
            if name not in h:
                problems.append(f"missing {name}")
        if problems:
            return problems
        if not re.fullmatch(r"\d{13}", h["Simlessly-Timestamp"]) or abs(time.time() * 1000 - int(h["Simlessly-Timestamp"])) > 600_000:
            problems.append("Simlessly-Timestamp not 13-digit ms within 10 minutes")
        if not UUID_RE.match(h["Simlessly-RequestID"]):
            problems.append("Simlessly-RequestID not a UUID v4")
        if h["Simlessly-RequestID"] in self._seen_ids:
            problems.append("Simlessly-RequestID reused")
        self._seen_ids.add(h["Simlessly-RequestID"])
        if not re.fullmatch(r"(?:UTC|GMT|[A-Za-z]+(?:/[A-Za-z0-9_+\-]+)+)", h["Simlessly-TimeZone"]):
            problems.append("Simlessly-TimeZone not an IANA zone")
        multipart = rec.path == "/api/v1/fleet/generateAc"
        if rec.method == "POST" and not multipart and h.get("Content-Type") != "application/json":
            problems.append("Content-Type")
        if multipart and not str(h.get("Content-Type", "")).startswith("multipart/form-data; boundary="):
            problems.append("Content-Type must be multipart/form-data with a boundary")
        if rec.method == "GET" and rec.body:
            problems.append("a GET must not carry a body")
        for name in ("AccessKey", "Signature", "Timestamp", "RequestID"):
            if name in h:
                problems.append(f"RSP-API header {name} must not be sent to the portal")
        return problems
