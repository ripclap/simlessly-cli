"""Client for the web portal's session API (not part of the documented OPEN API; it can change).

Differences from client.py:

* Authentication is a session token (`Simlessly-Token`), not an HMAC signature. The token grants
  the same access as the login, so it is stored like the API keys and never printed.
* Three fixed maps of path to HTTP method: SESSION_METHODS (login, logout), READ_METHODS and
  WRITE_METHODS, loaded from portal_endpoints.json. The caller never chooses the method. A GET sends a query string and no body. The
  portal answers a wrong method with HTTP 200 and code 10008.
* One entry point per kind of call, each refusing paths from the other maps before any network I/O:
  `read()` cannot reach a state-changing path, and `write()` / `write_multipart()` are used only
  behind the --yes gate (portal_write.py). A path in no map is refused.
* Same transport as client.HttpBase: pinned origin, no redirects, 1 MiB cap, no retries, no
  automatic login when the session expires.
* An invalid session arrives as HTTP 200 with code 10102, 10103 or 10206 and success false; it
  becomes PortalSessionExpired.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from importlib import resources
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlencode

from . import auth
from .client import DEFAULT_TIMEOUT, HttpBase, SimlesslyError, serialize
from .output import Redactor, debug_text

PATH_LOGIN = "/api/v1/user/login"
PATH_LOGOUT = "/api/v1/user/logout"

# Read-only calls.
PATH_FLEET_LIST = "/api/v1/fleet/list"
PATH_FLEET_RECYCLE_QUERY = "/api/v1/fleet/recycle/query"
PATH_FLEET_TRANSACTION = "/api/v1/fleet/transaction"
PATH_FLEET_QRCODE = "/api/v1/fleet/qrcode"            # POST; answers with a PNG, not an envelope (read_bytes)
PATH_LOG_PROFILE_LIST = "/api/v1/log/profile/list"
PATH_LOG_PROFILE_DETAIL = "/api/v1/log/profile/detail"
PATH_LOG_BATCH_TASK_LIST = "/api/v1/log/batch-task/list"
PATH_LOG_RECYCLE_LIST = "/api/v1/log/recycle/list"
PATH_CONFIG_NAME_QUERY = "/api/v1/config/name/query"
PATH_CONFIG_QUERY = "/api/v1/config/query"
PATH_CONFIG_DETAIL = "/api/v1/config/detail"
PATH_GROUP_LIST = "/api/v1/group/list"
PATH_CAMPAIGN_LIST = "/api/v1/campaign/list"
PATH_CAMPAIGN_RESOURCE_LIST = "/api/v1/campaign/resource/list"
PATH_BLOCK_LIST = "/api/v1/block/list"
PATH_EVENT_PROFILE_QUERY = "/api/v1/event/profile/query"
PATH_ANALYTIC_PERCENTAGE = "/api/v1/analytic/percentage"
PATH_ANALYTIC_DEVICE_BRAND = "/api/v1/analytic/deviceBrand"
PATH_ANALYTIC_PROFILE_STATUS = "/api/v1/analytic/profileStatus"
PATH_ANALYTIC_DOWNLOAD_BY_DAY = "/api/v1/analytic/downloadByDay"
PATH_ANALYTIC_DOWNLOAD_BY_MONTH = "/api/v1/analytic/downloadByMonth"
PATH_ANALYTIC_REDOWNLOAD = "/api/v1/analytic/redownload"
PATH_ANALYTIC_AC_COUNT = "/api/v1/analytic/ac-count"
PATH_ANALYTIC_LATEST_WEEK = "/api/v1/analytic/latest-week"
PATH_REPORT_CONFIG_QUERY = "/api/v1/report/config/query"
PATH_PLAN_QUERY_ORDER = "/api/v1/plan/queryOrder"
PATH_PLAN_LIST = "/api/v1/plan/list"
PATH_ORDER_LIST = "/api/v1/order/list"
PATH_ORDER_DETAIL = "/api/v1/order/detail"
PATH_ENTERPRISE_INFO = "/api/v1/enterprise/info"
PATH_ENTERPRISE_LIST = "/api/v1/enterprise/list"
PATH_ENUM_LIST = "/api/v1/enum/list"

# State-changing calls. Only the gate in portal_write.py reaches these.
PATH_FLEET_DELETE = "/api/v1/fleet/delete"
PATH_FLEET_UPDATE_NOTES = "/api/v1/fleet/update-notes"
PATH_FLEET_RE_GENERATE = "/api/v1/fleet/re-generate"
PATH_FLEET_RECYCLE = "/api/v1/fleet/recycle"
PATH_FLEET_GENERATE_AC = "/api/v1/fleet/generateAc"   # multipart/form-data (write_multipart)
PATH_GROUP_ADD = "/api/v1/group/add"
PATH_GROUP_BATCH = "/api/v1/group/batchGroup"

# The only portal paths the client calls, with the HTTP method of each. The data lives in
# portal_endpoints.json (groups: session, read, write; plus the list of multipart upload paths) so that
# tools/api_watch.py can update a method when the portal changes it. A path that is in no group is refused.
METHOD_POST, METHOD_GET = "POST", "GET"
ENDPOINTS_RESOURCE = "portal_endpoints.json"
_GROUPS = ("session", "read", "write")


def _load_endpoints(text: str) -> tuple[dict[str, dict[str, str]], frozenset[str]]:
    """Parse and check the endpoint data. Raises RuntimeError on any irregularity (fail closed at import)."""
    try:
        data = json.loads(text)
    except ValueError as err:
        raise RuntimeError(f"{ENDPOINTS_RESOURCE} is not valid JSON: {err}") from None
    if not isinstance(data, dict) or set(data) != {*_GROUPS, "multipart"}:
        raise RuntimeError(f"{ENDPOINTS_RESOURCE} must hold exactly the keys {', '.join((*_GROUPS, 'multipart'))}")
    seen: set[str] = set()
    groups: dict[str, dict[str, str]] = {}
    for name in _GROUPS:
        group = data[name]
        if not isinstance(group, dict) or not group:
            raise RuntimeError(f"{ENDPOINTS_RESOURCE}: group {name!r} must be a non-empty object")
        for path, method in group.items():
            if not (isinstance(path, str) and re.fullmatch(r"/api/v\d+/[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_\-]+)*", path)):
                raise RuntimeError(f"{ENDPOINTS_RESOURCE}: bad path {path!r}")
            if method not in (METHOD_GET, METHOD_POST):
                raise RuntimeError(f"{ENDPOINTS_RESOURCE}: bad method {method!r} for {path}")
            if path in seen:
                raise RuntimeError(f"{ENDPOINTS_RESOURCE}: {path} is listed in more than one group")
            if name == "write" and method != METHOD_POST:
                raise RuntimeError(f"{ENDPOINTS_RESOURCE}: {path} is in the write group and must be POST")
            seen.add(path)
        groups[name] = dict(group)
    if groups["session"].get(PATH_LOGIN) != METHOD_POST:        # a GET would put the credentials in the URL
        raise RuntimeError(f"{ENDPOINTS_RESOURCE}: {PATH_LOGIN} must be in the session group as POST")
    multipart = data["multipart"]
    if not isinstance(multipart, list) or not all(isinstance(p, str) for p in multipart):
        raise RuntimeError(f"{ENDPOINTS_RESOURCE}: 'multipart' must be a list of paths")
    stray = [p for p in multipart if p not in groups["write"] or groups["write"][p] != METHOD_POST]
    if stray:
        raise RuntimeError(f"{ENDPOINTS_RESOURCE}: multipart paths must be POST paths in the write group: {stray}")
    return groups, frozenset(multipart)


_GROUP_DATA, MULTIPART_PATHS = _load_endpoints(
    resources.files(__package__).joinpath(ENDPOINTS_RESOURCE).read_text(encoding="utf-8"))
SESSION_METHODS: Mapping[str, str] = MappingProxyType(_GROUP_DATA["session"])
READ_METHODS: Mapping[str, str] = MappingProxyType(_GROUP_DATA["read"])
WRITE_METHODS: Mapping[str, str] = MappingProxyType(_GROUP_DATA["write"])
BINARY_READ_PATHS = frozenset({PATH_FLEET_QRCODE})         # answer is a PNG: read_bytes() only
PORTAL_METHODS: Mapping[str, str] = MappingProxyType({**SESSION_METHODS, **READ_METHODS, **WRITE_METHODS})
PORTAL_PATHS = frozenset(PORTAL_METHODS)
READ_PATHS = frozenset(READ_METHODS)
WRITE_PATHS = frozenset(WRITE_METHODS)
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

WRONG_METHOD_CODE = "10008"          # "request method not support[Request method 'POST' not supported]"

SESSION_INVALID_CODES = frozenset({"10102", "10103", "10206"})
SESSION_EXPIRED_MESSAGE = "portal session expired or invalid; run: simlessly portal login"

_TZ_RE = re.compile(r"^(?:UTC|GMT|[A-Za-z]+(?:/[A-Za-z0-9_+\-]+)+)$")


class PortalSessionExpired(SimlesslyError):
    """The portal reports the session token as expired or invalid. Not retried."""

    def __init__(self) -> None:
        super().__init__(SESSION_EXPIRED_MESSAGE, kind="session")


def build_portal_url(base_url: str, path: str) -> str:
    if path not in PORTAL_METHODS:
        raise SimlesslyError(f"refusing to call portal path {path}: it is not one of the portal calls this tool implements",
                             kind="config")
    return base_url.rstrip("/") + path


def _query_value(value: Any) -> str:
    """One query-string value as the portal front-end writes it (booleans in lower case)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def encode_query(params: Mapping[str, Any] | None) -> str:
    """Percent-encoded query string without '?'; None values are dropped."""
    pairs = [(k, _query_value(v)) for k, v in (params or {}).items() if v is not None]
    return urlencode(pairs)


def md5_hex(password: str) -> str:
    """Lowercase hex MD5 of the password, as the portal's login form sends it (the portal's scheme, not local security)."""
    return hashlib.md5(password.encode("utf-8"), usedforsecurity=False).hexdigest()


def local_timezone(env: Mapping[str, str] | None = None) -> str:
    """IANA zone name a browser would send (TZ, else /etc/localtime), else 'UTC'."""
    env = os.environ if env is None else env
    name = (env.get("TZ") or "").strip().lstrip(":")
    if _TZ_RE.match(name):
        return name
    try:
        target = os.path.realpath("/etc/localtime")
    except OSError:
        return "UTC"
    marker = "zoneinfo/"
    if marker in target:
        name = target.split(marker, 1)[1]
        if _TZ_RE.match(name):
            return name
    return "UTC"


class PortalClient(HttpBase):
    _HEADER_REFUSED = ("request refused locally: a header value contains characters that are not allowed "
                       "(check the stored portal token); nothing was sent")

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        timezone: str = "UTC",
        timeout: float = DEFAULT_TIMEOUT,
        redactor: Redactor | None = None,
        debug: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(base_url, timeout=timeout, redactor=redactor, debug=debug)
        self._token = token
        self._timezone = timezone
        self.redactor.add(token)

    # ------------------------------------------------------------ entry points (each checks its own map)

    def session(self, path: str, data: Mapping[str, Any] | None = None) -> Any:
        """Login / logout. Returns the envelope's `obj`."""
        self._require(path, SESSION_METHODS, "session")
        return self._call(path, data)

    def read(self, path: str, data: Mapping[str, Any] | None = None) -> Any:
        """One read-only call; returns the envelope's `obj`. A state-changing path raises before any I/O.

        `data` is the JSON body for a POST path, the query parameters for a GET path."""
        self._require(path, READ_METHODS, "read-only")
        if path in BINARY_READ_PATHS:
            raise SimlesslyError(f"{path} answers with a file, not JSON: use read_bytes()", kind="config")
        return self._call(path, data)

    def read_bytes(self, path: str, data: Mapping[str, Any] | None = None) -> bytes:
        """A read-only call that answers with a PNG (the QR image); a JSON failure envelope becomes an error."""
        self._require(path, READ_METHODS, "read-only")
        if path not in BINARY_READ_PATHS:
            raise SimlesslyError(f"{path} does not answer with a file", kind="config")
        status, raw = self._exchange(path, data)
        if raw.startswith(PNG_MAGIC) and 200 <= status < 300:
            return raw
        self._open_failure(path, status, raw)
        raise SimlesslyError("the portal answered without an image", kind="parse", status=status)

    def write(self, path: str, data: Mapping[str, Any] | None = None) -> Any:
        """One state-changing JSON call, reached only through the --yes gate. Never retried."""
        self._require(path, WRITE_METHODS, "state-changing")
        if path in MULTIPART_PATHS:
            raise SimlesslyError(f"{path} takes a file upload: use write_multipart()", kind="config")
        return self._call(path, data)

    def write_multipart(self, path: str, fields: list[tuple[str, str]], filename: str, content: bytes) -> Any:
        """The multipart upload (generateAc): text fields, then one `file` part."""
        self._require(path, WRITE_METHODS, "state-changing")
        if path not in MULTIPART_PATHS:
            raise SimlesslyError(f"{path} does not take a file upload", kind="config")
        return self._call(path, None, multipart=(fields, filename, content))

    @staticmethod
    def _require(path: str, allowed: Mapping[str, str], kind: str) -> None:
        if path not in allowed:
            raise SimlesslyError(f"refusing to call portal path {path}: it is not one of the {kind} portal calls "
                                 "this tool implements", kind="config")

    # ------------------------------------------------------------ transport

    def _exchange(self, path: str, data: Mapping[str, Any] | None,
                  multipart: tuple[list[tuple[str, str]], str, bytes] | None = None) -> tuple[int, bytes]:
        url = build_portal_url(self.base_url, path)   # allowlist check first
        method = PORTAL_METHODS[path]
        headers = {
            "Simlessly-Timestamp": auth.new_timestamp(),
            "Simlessly-RequestID": auth.new_request_id(),
            "Simlessly-TimeZone": self._timezone,
        }
        shown = ""
        if multipart is not None:
            fields, filename, content = multipart
            boundary = "----simlessly-cli-" + auth.new_request_id()
            payload: bytes | None = encode_multipart(boundary, fields, filename, content)
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
            shown = "[multipart: " + ", ".join(f"{k}={v}" for k, v in fields) + f", file={filename} ({len(content)} bytes)]"
        elif method == METHOD_POST:
            text = serialize(dict(data or {}))
            payload = text.encode("utf-8")
            headers["Content-Type"] = "application/json"
            shown = text
        else:
            query = encode_query(data)
            url += ("?" + query) if query else ""
            payload = None                             # GET: no body
        if self._token and path != PATH_LOGIN:
            headers["Simlessly-Token"] = self._token   # omitted before login
        self._log_request(method, url, headers, shown, secret_body=(path == PATH_LOGIN))
        status, raw = self._send(url, headers, payload, method)
        self._log(f"< HTTP {status}, {len(raw)} bytes")
        if raw and not raw.startswith(PNG_MAGIC):
            self._log("< body: " + debug_text(raw.decode("utf-8", "replace"), self.redactor))
        return status, raw

    def _call(self, path: str, data: Mapping[str, Any] | None,
              multipart: tuple[list[tuple[str, str]], str, bytes] | None = None) -> Any:
        status, raw = self._exchange(path, data, multipart)
        return self._open_failure(path, status, raw)

    def _open_failure(self, path: str, status: int, raw: bytes) -> Any:
        """Open the envelope; session-invalid and wrong-method answers get their own errors."""
        method = PORTAL_METHODS[path]
        try:
            return self._open_envelope(status, raw)
        except SimlesslyError as err:
            if path != PATH_LOGIN and err.code in SESSION_INVALID_CODES:
                raise PortalSessionExpired() from None
            if err.code == WRONG_METHOD_CODE:
                raise SimlesslyError(
                    f"the portal rejected {method} {path} as the wrong request method (code {WRONG_METHOD_CODE}, "
                    "'request method not support'); the portal API may have changed since this tool was written "
                    "(it is not part of the documented OPEN API), so this command may need an update",
                    kind="api", status=err.status, code=err.code) from None
            raise

    def _log_request(self, method: str, url: str, headers: dict[str, str], text: str, *, secret_body: bool) -> None:
        if not self._debug:
            return
        self._log(f"> {method} {url}")
        for name, value in headers.items():
            self._log(f"> {name}: " + ("[redacted]" if name == "Simlessly-Token" else value))
        if method == METHOD_GET:
            return                                      # no body to show
        # The login body holds the e-mail address and the password hash.
        if secret_body:
            self._log("> body: [redacted: login credentials]")
        elif text.startswith("[multipart:"):
            self._log("> body: " + self.redactor.scrub(text))      # field names and file size, not the content
        else:
            self._log("> body: " + debug_text(text, self.redactor))


def encode_multipart(boundary: str, fields: list[tuple[str, str]], filename: str, content: bytes) -> bytes:
    """multipart/form-data as a browser writes it: text fields in order (arrays as repeated names), then the file."""
    def quote(text: str) -> str:
        return text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "")
    out = bytearray()
    for name, value in fields:
        out += (f'--{boundary}\r\nContent-Disposition: form-data; name="{quote(name)}"\r\n\r\n').encode("utf-8")
        out += value.encode("utf-8") + b"\r\n"
    out += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{quote(filename)}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode("utf-8")
    out += content + b"\r\n" + f"--{boundary}--\r\n".encode("utf-8")
    return bytes(out)
