"""ohttp -- Oblivious HTTP client, gateway and responder.

OHTTP exists so that the party who sees the content never sees who asked, and the party who
relays never sees the content.
"""

from __future__ import annotations

from . import apps, cli, client, crypto, gateway, keys, message, responder, svcb
from .client import request
from .crypto import supported_suites
from .gateway import relay
from .keys import generate_config, parse_config
from .message import decapsulate, encapsulate
from .svcb import select_gateway

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "cli",
    "client",
    "crypto",
    "decapsulate",
    "encapsulate",
    "gateway",
    "generate_config",
    "keys",
    "message",
    "parse_config",
    "relay",
    "request",
    "responder",
    "select_gateway",
    "supported_suites",
    "svcb",
]
