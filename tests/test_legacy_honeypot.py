from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from app import create_app
from honeypot import logger
from honeypot.honeypot import _event_from_payload, validate_bind


class HoneypotTests(unittest.TestCase):
    def test_loopback_bind_is_allowed(self) -> None:
        self.assertEqual(validate_bind("127.0.0.1", 8080), ("127.0.0.1", 8080))

    def test_external_bind_requires_explicit_expose(self) -> None:
        with self.assertRaises(ValueError):
            validate_bind("0.0.0.0", 8080)
        self.assertEqual(validate_bind("0.0.0.0", 8080, expose=True), ("0.0.0.0", 8080))

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


class FlaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def test_dashboard_security_headers(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
