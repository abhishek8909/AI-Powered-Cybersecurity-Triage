"""Security tests: sanitisation, validators, constant-time auth, headers, LRU rate limiting, and ReDoS."""

from __future__ import annotations

import time
import unittest

from src.security import (
    SECURITY_HEADERS,
    SlidingWindowRateLimiter,
    ValidationError,
    parse_alert_input,
    sanitize_text,
    validate_domain,
    validate_hash,
    validate_ip,
    validate_model_name,
    verify_bearer_token,
)


class TestSecurityControls(unittest.TestCase):
    def test_sanitize_strips_html_and_crlf_log_injection(self) -> None:
        malicious = "<script>alert(1)</script>SQLi\r\nFAKE_LOG_ENTRY\x00\tpayload"
        cleaned = sanitize_text(malicious)
        self.assertNotIn("<script>", cleaned)
        self.assertNotIn("\r", cleaned)
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertIn("SQLi", cleaned)

    def test_validators_reject_malformed_iocs_and_models(self) -> None:
        self.assertEqual(validate_ip("185.220.101.42"), "185.220.101.42")
        self.assertEqual(validate_ip("999.999.1.1"), "")
        self.assertEqual(validate_ip("127.0.0.1; rm -rf /"), "")

        self.assertEqual(validate_domain("Evil.Example"), "evil.example")
        self.assertEqual(validate_domain("bad..domain"), "")
        self.assertEqual(validate_domain(".leading.dot"), "")
        self.assertEqual(validate_domain("javascript:alert(1)"), "")

        self.assertEqual(validate_hash("44D88612FEA8A8F36DE82E1278ABB02F"), "44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(validate_hash("not-a-hash"), "")

        self.assertEqual(validate_model_name("gemini-2.5-flash"), "gemini-2.5-flash")
        self.assertEqual(validate_model_name("../evil/path"), "gemini-2.0-flash")

    def test_bearer_token_verification(self) -> None:
        self.assertTrue(verify_bearer_token(None, ""))
        self.assertFalse(verify_bearer_token(None, "secret"))
        self.assertFalse(verify_bearer_token("Basic abc", "secret"))
        self.assertFalse(verify_bearer_token("Bearer wrong", "secret"))
        self.assertTrue(verify_bearer_token("Bearer secret", "secret"))

    def test_parse_alert_rejects_invalid_structures(self) -> None:
        with self.assertRaises(ValidationError):
            parse_alert_input("not-a-dict")
        with self.assertRaises(ValidationError):
            parse_alert_input({"source_ip": "1.2.3.4"})

    def test_sliding_window_rate_limiter_enforces_retry_after_and_lru_eviction(self) -> None:
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=10.0, max_clients=2)
        self.assertEqual(limiter.check("c1", now=100.0), (True, 0))
        self.assertEqual(limiter.check("c1", now=101.0), (True, 0))
        allowed, retry_after = limiter.check("c1", now=102.0)
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)

        # LRU eviction bounds memory to max_clients=2.
        limiter.check("c2", now=103.0)
        limiter.check("c3", now=104.0)
        self.assertEqual(limiter.client_count, 2)

        # Recovers after window expires.
        self.assertTrue(limiter.allow("c2", now=115.0))

    def test_redos_resistance_on_long_adversarial_input(self) -> None:
        adversarial = "<" + ("a" * 50_000)
        start = time.perf_counter()
        result = sanitize_text(adversarial, max_len=2000)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.assertLess(elapsed_ms, 50.0, f"Sanitizer took too long: {elapsed_ms:.2f}ms")
        self.assertLessEqual(len(result), 2000)

    def test_required_security_headers_and_strict_csp(self) -> None:
        for header in (
            "Content-Security-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ):
            self.assertIn(header, SECURITY_HEADERS)
        self.assertNotIn("unsafe-inline", SECURITY_HEADERS["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
