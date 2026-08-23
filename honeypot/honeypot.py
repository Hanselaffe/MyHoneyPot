"""Small bounded TCP honeypot sensor for local defensive labs."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import threading
from contextlib import closing

from honeypot import logger

_MAX_READ_BYTES = 1024


def validate_bind(bind_host: str, port: int, *, expose: bool = False) -> tuple[str, int]:
    host = bind_host.strip()
    if not host:
        raise ValueError("bind host must not be empty")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host != "localhost":
            raise ValueError("bind host must be a literal IP address or localhost")
        address = ipaddress.ip_address("127.0.0.1")
        host = "127.0.0.1"

    if not address.is_loopback and not expose:
        raise ValueError("non-loopback binding requires explicit expose=True")
    return host, port


def _event_from_payload(addr: tuple[str, int], payload: bytes) -> dict[str, object]:
    return {
        "event_type": "connection_data",
        "source_ip": addr[0],
        "source_port": int(addr[1]),
        "received_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def start_honeypot(
    bind_host: str = "127.0.0.1",
    port: int = 8080,
    *,
    expose: bool = False,
    stop_event: threading.Event | None = None,
    max_read_bytes: int = _MAX_READ_BYTES,
    client_timeout: float = 2.0,
) -> None:
    """Run a bounded single-threaded TCP sensor until *stop_event* is set."""
    host, port = validate_bind(bind_host, port, expose=expose)
    if not 1 <= max_read_bytes <= 4096:
        raise ValueError("max_read_bytes must be between 1 and 4096")
    if not 0.1 <= client_timeout <= 10.0:
        raise ValueError("client_timeout must be between 0.1 and 10 seconds")

    stopper = stop_event or threading.Event()

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(16)
        server_socket.settimeout(0.5)

        logger.log_event(
            {
                "event_type": "sensor_started",
                "bind_host": host,
                "port": port,
                "external_exposure_requested": expose,
            }
        )

        try:
            while not stopper.is_set():
                try:
                    client_socket, addr = server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if stopper.is_set():
                        break
                    raise

                with closing(client_socket):
                    client_socket.settimeout(client_timeout)
                    try:
                        payload = client_socket.recv(max_read_bytes)
                    except (socket.timeout, ConnectionError, OSError):
                        payload = b""
                    logger.log_event(_event_from_payload((str(addr[0]), int(addr[1])), payload))
        finally:
            logger.log_event({"event_type": "sensor_stopped", "bind_host": host, "port": port})
