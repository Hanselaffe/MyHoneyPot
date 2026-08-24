from __future__ import annotations

import argparse
import threading

from app import create_app
from honeypot.honeypot import start_honeypot, validate_bind


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the legacy metadata-only TCP honeypot and local dashboard")
    parser.add_argument("--sensor-host", default="127.0.0.1", help="sensor bind address; loopback by default")
    parser.add_argument("--sensor-port", type=int, default=8080, help="sensor TCP port")
    parser.add_argument(
        "--expose",
        action="store_true",
        help="explicitly permit a non-loopback sensor bind; network containment remains the operator's responsibility",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        host, port = validate_bind(args.sensor_host, args.sensor_port, expose=args.expose)
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return 2

    stop_event = threading.Event()
    sensor = threading.Thread(
        target=start_honeypot,
        kwargs={"bind_host": host, "port": port, "expose": args.expose, "stop_event": stop_event},
        name="legacy-honeypot-sensor",
        daemon=True,
    )
    sensor.start()

    app = create_app()
    try:
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    finally:
        stop_event.set()
        sensor.join(timeout=3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
