"""Legacy metadata-only honeypot package."""

from .honeypot import start_honeypot, validate_bind

__all__ = ["start_honeypot", "validate_bind"]
