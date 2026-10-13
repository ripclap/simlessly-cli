"""Request signing for the Simlessly RSP API.

    signData  = Timestamp + RequestID + AccessKey + RequestBody
    Signature = HMAC-SHA256(key=SecretKey, message=signData), hex, uppercase

Timestamp is epoch milliseconds (valid for 10 minutes). RequestID is a new UUID per request and
can be used once. RequestBody is the exact JSON text sent. The signature does not cover the URL,
so client.py pins the host and paths. Header names have no hyphens.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid


def new_timestamp() -> str:
    """Epoch milliseconds as a decimal string."""
    return str(int(time.time() * 1000))


def new_request_id() -> str:
    """A new UUID v4."""
    return str(uuid.uuid4())


def sign(secret_key: str, timestamp: str, request_id: str, access_key: str, body: str) -> str:
    """Return the 64-character uppercase hex HMAC-SHA256 signature."""
    sign_data = timestamp + request_id + access_key + body
    digest = hmac.new(secret_key.encode("utf-8"), sign_data.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest().upper()


def build_headers(
    access_key: str,
    secret_key: str,
    body: str,
    *,
    timestamp: str | None = None,
    request_id: str | None = None,
) -> dict[str, str]:
    """Headers for one signed POST. `body` must be the exact text sent."""
    timestamp = timestamp or new_timestamp()
    request_id = request_id or new_request_id()
    return {
        "Content-Type": "application/json",
        "AccessKey": access_key,
        "Timestamp": timestamp,
        "RequestID": request_id,
        "Signature": sign(secret_key, timestamp, request_id, access_key, body),
    }
