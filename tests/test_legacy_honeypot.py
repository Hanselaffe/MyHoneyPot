from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from honeypot import logger
from honeypot.honeypot import _event_from_payload, start_honeypot, validate_bind


class HoneypotTests(unittest.TestCase):
    def test_loopback_bind_is_allowed(self) -> None:
        self.assertEqual(validate_bind("127.0.0.1", 8080), ("127.0.0.1", 8080))
        self.assertEqual(validate_bind("localhost", 8080), ("127.0.0.1", 8080))

    def test_external_bind_requires_explicit_expose(self) -> None:
        with self.assertRaises(ValueError):
            validate_bind("0.0.0.0", 8080)
        self.assertEqual(validate_bind("0.0.0.0", 8080, expose=True), ("0.0.0.0", 8080))

    def test_ipv6_bind_is_rejected_before_socket_creation(self) -> None:
        with self.assertRaisesRegex(ValueError, "IPv4 binds only"):
            validate_bind("::1", 8080)

    def test_sensor_read_and_timeout_bounds_fail_before_socket_creation(self) -> None:
        for max_read_bytes in (0, 4097, True):
            with self.assertRaises(ValueError):
                start_honeypot(max_read_bytes=max_read_bytes)
        for client_timeout in (0.05, 10.1, True):
            with self.assertRaises(ValueError):
                start_honeypot(client_timeout=client_timeout)

    def test_event_contains_digest_not_raw_payload(self) -> None:
        payload = b"secret-looking-test-data"
        event = _event_from_payload(("192.0.2.10", 12345), payload)
        self.assertEqual(event["received_bytes"], len(payload))
        self.assertEqual(event["payload_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertNotIn(payload.decode(), repr(event))

    def test_jsonl_logger_does_not_store_raw_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            logger.log_event(
                {
                    "event_type": "connection_data",
                    "source_ip": "192.0.2.1",
                    "received_bytes": 4,
                    "payload_sha256": hashlib.sha256(b"test").hexdigest(),
                },
                log_file=path,
            )
            content = path.read_text(encoding="utf-8")
            self.assertNotIn('"data"', content)
            records = logger.get_logs(log_file=path)
            self.assertEqual(records[0]["received_bytes"], 4)

    def test_jsonl_log_rotates_when_size_limit_is_reached(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with patch.object(logger, "_MAX_LOG_BYTES", 1):
                logger.log_event({"event_type": "first"}, log_file=path)
                logger.log_event({"event_type": "second"}, log_file=path)

            rotated = path.with_suffix(path.suffix + ".1")
            self.assertTrue(rotated.is_file())
            self.assertEqual(logger.get_logs(log_file=rotated)[0]["event_type"], "first")
            self.assertEqual(logger.get_logs(log_file=path)[0]["event_type"], "second")


class FlaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def test_dashboard_security_headers(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    @patch("app.routes.logger.get_logs", return_value=[])
    def test_dashboard_requests_only_recent_events(self, get_logs_mock) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        get_logs_mock.assert_called_once_with(limit=200)


if __name__ == "__main__":
    unittest.main()
