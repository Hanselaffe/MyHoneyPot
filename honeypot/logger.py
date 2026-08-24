"""Privacy-minimized JSONL event logging for the legacy honeypot."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_FILE = Path("data") / "honeypot.jsonl"
_MAX_LOG_BYTES = 5 * 1024 * 1024
_LOCK = threading.Lock()


def _rotate_if_needed(path: Path) -> None:
    if not path.exists() or path.stat().st_size < _MAX_LOG_BYTES:
        return
    rotated = path.with_suffix(path.suffix + ".1")
    rotated.unlink(missing_ok=True)
    os.replace(path, rotated)


def log_event(event: dict[str, Any], *, log_file: str | Path = LOG_FILE) -> None:
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = dict(event)
    record.setdefault("timestamp_utc", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    with _LOCK:
        _rotate_if_needed(path)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")


def get_logs(*, log_file: str | Path = LOG_FILE, limit: int = 200) -> list[dict[str, Any]]:
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    path = Path(log_file)
    if not path.is_file():
        return []

    with _LOCK:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    records: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def log_attack(ip: str, data: str | bytes) -> None:
    """Backward-compatible API that intentionally does not retain raw payloads."""
    import hashlib

    payload = data.encode("utf-8", errors="replace") if isinstance(data, str) else bytes(data)
    log_event(
        {
            "event_type": "connection_data",
            "source_ip": str(ip),
            "received_bytes": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
    )
