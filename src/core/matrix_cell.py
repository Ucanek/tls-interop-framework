"""Typed matrix cell for TLS interop runs (replaces ``dict[str, str]`` cells)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping, Sequence

from core.utils import parse_asymmetric, split_asymmetric_csv


@dataclass(frozen=True)
class MatrixCell:
    server: str
    client: str
    tls_version: str = ""
    cipher_suite: str = ""
    supported_groups: str = ""
    signature_schemes: str = ""
    alpn: str = ""
    test_features: str = ""
    tls_port: str = ""
    expect_hrr: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> MatrixCell:
        def _text(key: str) -> str:
            return str(data.get(key, "") or "").strip()

        return cls(
            server=_text("server").lower(),
            client=_text("client").lower(),
            tls_version=_text("tls_version"),
            cipher_suite=_text("cipher_suite"),
            supported_groups=_text("supported_groups"),
            signature_schemes=_text("signature_schemes"),
            alpn=_text("alpn"),
            test_features=_text("test_features"),
            tls_port=_text("tls_port"),
            expect_hrr=_text("expect_hrr"),
        )

    @classmethod
    def from_axis(cls, axis_keys: Sequence[str], values: Sequence[Any]) -> MatrixCell:
        return cls.from_mapping({k: v for k, v in zip(axis_keys, values)})

    def to_mapping(self) -> dict[str, str]:
        return asdict(self)

    def get(self, key: str, default: str = "") -> str:
        if key in self.to_mapping():
            val = getattr(self, key)
            return str(val) if val else default
        return default

    def scalar(self, field: str, *, server: bool) -> str:
        raw = (getattr(self, field, "") or "").strip()
        if not raw:
            return ""
        if ":" in raw:
            left, right = parse_asymmetric(raw)
            return left if server else right
        return raw

    def list_tokens(self, field: str, *, server: bool) -> list[str]:
        raw = (getattr(self, field, "") or "").strip()
        if not raw:
            return []
        left, right = split_asymmetric_csv(raw)
        return list(left if server else right)

    def cipher_id(self, *, server: bool) -> str:
        return self.scalar("cipher_suite", server=server)

    def truthy(self, field: str) -> bool:
        return (getattr(self, field, "") or "").strip().lower() in ("true", "1", "yes", "on")

    def with_fields(self, **kwargs: Any) -> MatrixCell:
        return replace(self, **kwargs)
