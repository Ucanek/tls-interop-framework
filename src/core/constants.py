"""Shared TLS catalog tokens (avoid magic strings across validation and wrappers)."""

from __future__ import annotations

from enum import Enum


class TlsFeature(str, Enum):
    PSK = "psk"
    ANONYMOUS = "anonymous"
    RESUMPTION = "resumption"
    ZERO_RTT = "0rtt"
    MTLS = "mtls"


class TlsVersionLabel(str, Enum):
    V12 = "1.2"
    V13 = "1.3"
