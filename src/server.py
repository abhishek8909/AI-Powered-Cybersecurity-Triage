"""Secure threaded HTTP server for PS06 AI-Powered Cybersecurity Triage."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
from typing import Any

from src.sample_data import SAMPLE_ALERTS
from src.security import (
    MAX_BATCH_SIZE,
    MAX_BODY_BYTES,
    SECURITY_HEADERS,
    SlidingWindowRateLimiter,
    ValidationError,
    parse_alert_input,
    verify_bearer_token,
)
from src.triage_engine import triage_batch

logger = logging.getLogger("ps06.server")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Explicit static asset allowlist prevents path traversal completely.
STATIC_ALLOWLIST: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


class _HTTPError(Exception):
    """Internal typed HTTP error carrying status code and safe client message."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _load_static_cache() -> dict[str, tuple[bytes, str]]:
    """Load allowlisted static assets into memory once at server startup."""
    cache: dict[str, tuple[bytes, str]] = {}
    for route, (filename, content_type) in STATIC_ALLOWLIST.items():
        file_path = STATIC_DIR / filename
        if file_path.is_file():
            cache[route] = (file_path.read_bytes(), content_type)
    return cache


class TriageHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying rate limiter, optional API token, and cached static assets."""

    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        rate_limit_per_min: int = 120,
        api_token: str | None = None,
    ) -> None:
        self.rate_limiter = SlidingWindowRateLimiter(max_requests=rate_limit_per_min, window_seconds=60.0)
        self.api_token = os.environ.get("TRIAGE_API_TOKEN", "").strip() if api_token is None else api_token
        self.static_cache = _load_static_cache()
        super().__init__(server_address, TriageRequestHandler)


class TriageRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for SOC triage REST API and accessible dashboard assets."""

    server: TriageHTTPServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Suppress default stderr request spam during tests unless VERBOSE_LOGS=1."""
        if os.environ.get("VERBOSE_LOGS") == "1":
            super().log_message(format, *args)

    def _send_security_headers(self) -> None:
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._send_security_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_rate_limit(self) -> bool:
        client_ip = self.client_address[0] if self.client_address else "unknown"
        allowed, retry_after = self.server.rate_limiter.check(client_ip)
        if not allowed:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Rate limit exceeded. Please retry shortly."},
                extra_headers={"Retry-After": str(retry_after)},
            )
            return False
        return True

    def _check_auth(self) -> bool:
        if not verify_bearer_token(self.headers.get("Authorization"), self.server.api_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Unauthorized. Valid Bearer token required."},
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return False
        return True

    def _read_json_body(self) -> Any:
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise _HTTPError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json.",
            )

        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise _HTTPError(HTTPStatus.LENGTH_REQUIRED, "Missing Content-Length header.")
        try:
            content_length = int(raw_len)
        except ValueError as exc:
            raise _HTTPError(HTTPStatus.BAD_REQUEST, "Invalid Content-Length header.") from exc

        if content_length <= 0:
            raise _HTTPError(HTTPStatus.BAD_REQUEST, "Request body must not be empty.")
        if content_length > MAX_BODY_BYTES:
            raise _HTTPError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"Request body exceeds maximum size of {MAX_BODY_BYTES} bytes.",
            )

        raw_bytes = self.rfile.read(content_length)
        try:
            return json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _HTTPError(HTTPStatus.BAD_REQUEST, "Malformed JSON payload.") from exc

    def _serve_static(self, path: str, head_only: bool = False) -> bool:
        entry = self.server.static_cache.get(path)
        if entry is None:
            return False
        data, content_type = entry
        self.send_response(HTTPStatus.OK)
        self._send_security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head_only:
            self.wfile.write(data)
        return True

    def do_HEAD(self) -> None:  # noqa: N802
        """Handle HEAD requests for health and cached static UI assets."""
        path = self.path.split("?", 1)[0]
        if path == "/api/health":
            self.send_response(HTTPStatus.OK)
            self._send_security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            return
        if self._serve_static(path, head_only=True):
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self._send_security_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests for health, sample alerts, and cached static UI assets."""
        path = self.path.split("?", 1)[0]

        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "service": "ps06-cyber-triage"})
            return

        if path == "/api/sample-alerts":
            if not self._check_rate_limit():
                return
            self._send_json(HTTPStatus.OK, {"alerts": SAMPLE_ALERTS})
            return

        if self._serve_static(path, head_only=False):
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Resource not found."})

    def do_POST(self) -> None:  # noqa: N802
        """Handle POST requests for single and batch cybersecurity alert triage."""
        if not self._check_rate_limit():
            return

        path = self.path.split("?", 1)[0]
        if path not in {"/api/triage", "/api/triage/batch"}:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
            return

        if not self._check_auth():
            return

        try:
            payload = self._read_json_body()
            if path == "/api/triage":
                alert = parse_alert_input(payload, fallback_index=0)
                result = triage_batch([alert], use_external_llm=bool(payload.get("use_llm", False)))
                self._send_json(HTTPStatus.OK, result.to_dict())
                return

            if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
                raise ValidationError("Batch payload must be an object with an 'alerts' list.")

            raw_alerts = payload["alerts"]
            if not raw_alerts:
                raise ValidationError("'alerts' list must contain at least one alert.")
            if len(raw_alerts) > MAX_BATCH_SIZE:
                raise ValidationError(f"Batch exceeds maximum allowed size of {MAX_BATCH_SIZE} alerts.")

            parsed_alerts = [parse_alert_input(item, idx) for idx, item in enumerate(raw_alerts)]
            use_llm = bool(payload.get("use_llm", False))
            result = triage_batch(parsed_alerts, use_external_llm=use_llm)
            self._send_json(HTTPStatus.OK, result.to_dict())
        except _HTTPError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except ValidationError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception:  # noqa: BLE001
            logger.exception("Unhandled error during triage request")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal triage processing error."})


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the cybersecurity triage HTTP server."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server = TriageHTTPServer((host, port))
    print(f"PS06 AI Cybersecurity Triage running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
    )
