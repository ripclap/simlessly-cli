"""HTTP client for the Simlessly RSP API: one signed POST at a time.

* Every call is a POST with a compact JSON body; the signed text is the sent text (see auth.py).
* Only the paths below can be called, and only on the pinned origin, because the signature
  does not cover the URL.
* Redirects are refused, responses are capped at 1 MiB, proxy settings are ignored.
* http.client is used instead of urllib to keep header case (urllib rewrites "AccessKey" to "Accesskey").
* No automatic retries. After an unknown result on a state-changing call, check the profile first.
* An answer succeeds or fails by the envelope's boolean `success`, not by `code`.
"""

from __future__ import annotations

import http.client
import json
import ssl
from typing import Any, Callable
from urllib.parse import urlsplit

from . import auth
from .output import Redactor, clean, debug_text, mask_text

MAX_RESPONSE_BYTES = 1 << 20  # 1 MiB
DEFAULT_TIMEOUT = 20.0

# The only endpoints the RSP client calls (all POST).
PATH_CONFIG_LIST = "/api/v1/config/list"
PATH_GENERATE_AC = "/api/v2/ac/generate"          # v2; every other RSP call is v1
PATH_BATCH_INFO = "/api/v1/batch/info"
PATH_PROFILE_DETAIL = "/api/v1/profile/detail"
PATH_PROFILE_LOG = "/api/v1/profile/log"
PATH_PROFILE_EXPIRED = "/api/v1/profile/expired"
PATH_PROFILE_DELETE = "/api/v1/profile/delete"
PATH_ES2_CANCEL = "/gsma/rsp2/es2plus/cancelOrder"
PATH_ES2_DOWNLOAD = "/gsma/rsp2/es2plus/downloadOrder"
PATH_ES2_CONFIRM = "/gsma/rsp2/es2plus/confirmOrder"
ALLOWED_PATHS = frozenset({
    PATH_CONFIG_LIST, PATH_GENERATE_AC, PATH_BATCH_INFO, PATH_PROFILE_DETAIL, PATH_PROFILE_LOG,
    PATH_PROFILE_EXPIRED, PATH_PROFILE_DELETE, PATH_ES2_CANCEL, PATH_ES2_DOWNLOAD, PATH_ES2_CONFIRM,
})

# Failures after which the server may have acted.
_UNKNOWN_KINDS = {"timeout", "dropped", "redirect", "too_large", "parse"}


class SimlesslyError(Exception):
    """A failed call. Messages are already scrubbed.

    kinds: config, timeout, connect, dropped, redirect, too_large, parse, http, api
    """

    def __init__(self, message: str, *, kind: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.code = code

    @property
    def outcome_unknown(self) -> bool:
        """True when the vendor may have acted."""
        return self.kind in _UNKNOWN_KINDS or (self.kind == "http" and (self.status or 0) >= 500)


def build_url(base_url: str, path: str) -> str:
    if path not in ALLOWED_PATHS:
        raise SimlesslyError(f"refusing to call unknown path {path}", kind="config")
    return base_url.rstrip("/") + path


def serialize(body: dict[str, Any]) -> str:
    """Compact JSON; None values dropped."""
    return json.dumps({k: v for k, v in body.items() if v is not None},
                      separators=(",", ":"), ensure_ascii=False)


class HttpBase:
    """Shared transport: one request on a pinned origin, no redirects, 1 MiB cap, no retries.

    Subclasses add authentication headers and a path allowlist (Client: signed RSP API; PortalClient: portal session API).
    """

    # http.client's own message quotes the rejected header value, so use this instead.
    _HEADER_REFUSED = ("request refused locally: a header value contains characters that are not allowed; "
                       "nothing was sent")

    def __init__(self, base_url: str, *, timeout: float = DEFAULT_TIMEOUT, redactor: Redactor | None = None,
                 debug: Callable[[str], None] | None = None) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.redactor = redactor or Redactor()
        self._debug = debug

    # ------------------------------------------------------------ internals

    def _send(self, url: str, headers: dict[str, str], data: bytes | None, method: str = "POST") -> tuple[int, bytes]:
        parts = urlsplit(url)
        target = parts.path + ("?" + parts.query if parts.query else "")
        if parts.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                parts.hostname, parts.port, timeout=self.timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=self.timeout)
        sent = False  # True once the whole request is on the wire
        try:
            try:
                conn.request(method, target, body=data, headers=headers)
            except (ValueError, UnicodeError):
                # Bad header value, rejected before sending. http.client's message quotes it, so say nothing.
                raise SimlesslyError(self._HEADER_REFUSED, kind="config") from None
            sent = True
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                raise SimlesslyError(f"server answered with a redirect (HTTP {resp.status}); redirects are refused",
                                     kind="redirect", status=resp.status)
            declared = resp.getheader("Content-Length", "")
            if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                raise SimlesslyError("response larger than 1 MiB", kind="too_large")
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise SimlesslyError("response larger than 1 MiB", kind="too_large")
            return resp.status, raw
        except SimlesslyError:
            raise
        except TimeoutError:
            raise SimlesslyError(f"no answer within {self.timeout:g}s", kind="timeout") from None
        except (ConnectionResetError, BrokenPipeError, http.client.HTTPException):
            raise SimlesslyError("connection dropped before an answer arrived", kind="dropped") from None
        except OSError as err:  # refused, DNS failure, TLS/certificate failure...
            if sent:
                # The request was written, so the vendor may have acted: not "could not connect".
                raise SimlesslyError("connection failed after the request was sent ("
                                     + self._scrub(type(err).__name__, 60) + "); the vendor may have acted",
                                     kind="dropped") from None
            raise SimlesslyError("could not connect: " + self._scrub(f"{type(err).__name__}: {err}", 200),
                                 kind="connect") from None
        finally:
            conn.close()

    def _open_envelope(self, status: int, raw: bytes) -> Any:
        ok_status = 200 <= status < 300
        text = raw.decode("utf-8", "replace").strip()
        envelope: Any = None
        if text:
            try:
                envelope = json.loads(text)
            except ValueError:
                raise SimlesslyError(f"HTTP {status}: unreadable answer: {self._scrub(text, 200)}",
                                     kind="parse" if ok_status else "http", status=status) from None
        if not isinstance(envelope, dict):
            envelope = None
        code = envelope.get("code") if envelope else None
        code = code.strip() if isinstance(code, str) else None
        msg = envelope.get("msg") if envelope else None
        msg = self._scrub(msg, 200) if isinstance(msg, str) and msg.strip() else None

        if not ok_status:
            raise SimlesslyError(f"HTTP {status}: {msg or http.client.responses.get(status, 'error')}",
                                 kind="http", status=status, code=code)
        if envelope is None or not isinstance(envelope.get("success"), bool):
            raise SimlesslyError(f"HTTP {status}: the answer is not a result envelope", kind="parse", status=status)
        if envelope["success"] is False:
            detail = msg or "no message"
            raise SimlesslyError(f"Simlessly refused the request: {detail}" + (f" (code {code})" if code else ""),
                                 kind="api", status=status, code=code)
        return envelope.get("obj")

    def _scrub(self, text: str, limit: int | None = None) -> str:
        return clean(mask_text(str(text), self.redactor), limit)

    def _log(self, line: str) -> None:
        if self._debug:
            self._debug(line)


class Client(HttpBase):
    _HEADER_REFUSED = ("request refused locally: a header value contains characters that "
                       "are not allowed (check the access key); nothing was sent")

    def __init__(
        self,
        base_url: str,
        access_key: str,
        secret_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        redactor: Redactor | None = None,
        debug: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(base_url, timeout=timeout, redactor=redactor, debug=debug)
        self._access_key = access_key
        self._secret_key = secret_key
        self.redactor.add(access_key, secret_key)

    # ------------------------------------------------------------ public

    def post(self, path: str, body: dict[str, Any]) -> Any:
        """Send one signed POST and return the envelope's `obj` (may be None)."""
        url = build_url(self.base_url, path)
        text = serialize(body)                          # serialize once
        headers = auth.build_headers(self._access_key, self._secret_key, text)  # sign that text
        self._log_request(url, headers, text)
        status, raw = self._send(url, headers, text.encode("utf-8"))
        self._log(f"< HTTP {status}, {len(raw)} bytes")
        if raw:
            self._log("< body: " + debug_text(raw.decode("utf-8", "replace"), self.redactor))
        return self._open_envelope(status, raw)

    def _log_request(self, url: str, headers: dict[str, str], text: str) -> None:
        if not self._debug:
            return
        self._log(f"> POST {url}")
        for name, value in headers.items():
            shown = "[redacted]" if name in ("AccessKey", "Signature") else value
            self._log(f"> {name}: {shown}")
        self._log("> body: " + debug_text(text, self.redactor))
