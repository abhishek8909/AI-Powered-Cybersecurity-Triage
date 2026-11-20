"""Security controls: validation, sanitisation, constant-time auth, LRU rate limiting, and headers."""

from __future__ import annotations

from collections import OrderedDict, deque
import hmac
import ipaddress
import math
import re
import threading
import time
from typing import Any

from src.models import AlertInput

MAX_BODY_BYTES = 1_048_576  # 1 MiB
MAX_BATCH_SIZE = 5_000
MAX_SHORT_FIELD = 128
MAX_TEXT_FIELD = 2_000

# Pre-compiled, ReDoS-safe linear patterns (no nested quantifiers).
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_HTML_TAG_RE = re.compile(r"<[^>]{0,256}>")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")
_HEX_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
_MODEL_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
}


class ValidationError(ValueError):
    """Raised when incoming payload fails strict security validation."""


def sanitize_text(value: Any, max_len: int = MAX_TEXT_FIELD) -> str:
    """Strip control/CRLF characters and HTML tags to prevent log injection & XSS.

    Time complexity: O(len(value)).
    """
    if value is None:
        return ""
    text = str(value)
    if len(text) > max_len * 2:
        text = text[: max_len * 2]
    text = _CONTROL_CHARS_RE.sub(" ", text)
    text = _HTML_TAG_RE.sub("", text)
    return " ".join(text.split())[:max_len]


def validate_ip(value: Any) -> str:
    """Return normalized IPv4/IPv6 string or empty string if omitted/invalid."""
    raw = sanitize_text(value, max_len=64)
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def validate_domain(value: Any) -> str:
    """Return sanitized lowercase domain name if structurally valid."""
    raw = sanitize_text(value, max_len=253).lower()
    if raw and _DOMAIN_RE.match(raw) and "." in raw and ".." not in raw and not raw.startswith("."):
        return raw
    return ""


def validate_hash(value: Any) -> str:
    """Return lowercase hex file hash (MD5/SHA1/SHA256) if valid."""
    raw = sanitize_text(value, max_len=64).lower()
    if raw and _HEX_HASH_RE.match(raw):
        return raw
    return ""


def validate_model_name(value: str, default: str = "gemini-2.0-flash") -> str:
    """Validate LLM model identifier to prevent URL path injection."""
    cleaned = value.strip()
    if cleaned and _MODEL_NAME_RE.match(cleaned) and ".." not in cleaned:
        return cleaned
    return default


def verify_bearer_token(auth_header: str | None, expected_token: str) -> bool:
    """Verify Authorization: Bearer <token> in constant time."""
    if not expected_token:
        return True
    if not auth_header:
        return False
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return hmac.compare_digest(parts[1].strip(), expected_token)


def parse_alert_input(payload: Any, fallback_index: int = 0) -> AlertInput:
    """Validate and normalize an untrusted dictionary into an AlertInput."""
    if not isinstance(payload, dict):
        raise ValidationError("Each alert must be a JSON object.")

    title = sanitize_text(payload.get("title"), max_len=200)
    description = sanitize_text(payload.get("description"), max_len=MAX_TEXT_FIELD)
    if not title and not description:
        raise ValidationError("Alert must include a non-empty 'title' or 'description'.")

    alert_id = sanitize_text(payload.get("alert_id"), max_len=64) or f"ALT-{fallback_index + 1:04d}"
    raw_sev = sanitize_text(payload.get("raw_severity", "medium"), max_len=16).lower()
    if raw_sev not in _VALID_SEVERITIES:
        raw_sev = "medium"

    return AlertInput(
        alert_id=alert_id,
        title=title or description[:80],
        description=description or title,
        source_ip=validate_ip(payload.get("source_ip")),
        dest_host=sanitize_text(payload.get("dest_host"), max_len=MAX_SHORT_FIELD),
        user=sanitize_text(payload.get("user"), max_len=MAX_SHORT_FIELD),
        domain=validate_domain(payload.get("domain")),
        file_hash=validate_hash(payload.get("file_hash")),
        category=sanitize_text(payload.get("category", "general"), max_len=64).lower() or "general",
        raw_severity=raw_sev,
        timestamp=sanitize_text(payload.get("timestamp"), max_len=64),
    )


class SlidingWindowRateLimiter:
    """Thread-safe per-client sliding-window rate limiter with LRU key eviction.

    Time complexity: O(1) amortized per check.
    """

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        max_clients: int = 10_000,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._max_clients = max_clients
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._buckets)

    def check(self, client_key: str, now: float | None = None) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        ts = time.monotonic() if now is None else now
        cutoff = ts - self._window_seconds
        with self._lock:
            bucket = self._buckets.get(client_key)
            if bucket is None:
                while len(self._buckets) >= self._max_clients:
                    self._buckets.popitem(last=False)
                bucket = deque()
                self._buckets[client_key] = bucket
            else:
                self._buckets.move_to_end(client_key)

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self._max_requests:
                retry_after = max(1, math.ceil((bucket[0] + self._window_seconds) - ts))
                return False, retry_after

            bucket.append(ts)
            return True, 0

    def allow(self, client_key: str, now: float | None = None) -> bool:
        """Return True if client is within rate limit, False otherwise."""
        allowed, _ = self.check(client_key, now=now)
        return allowed
