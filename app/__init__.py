from __future__ import annotations

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)

    from .routes import main

    app.register_blueprint(main)

    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
        return response

    return app
