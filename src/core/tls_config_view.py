"""Typed read accessors for ``interop_pb2.TlsConfig`` (protobuf stays on the wire)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TypeAlias, Union

from interop_proto import interop_pb2


class TlsConfigView:
    """Thin wrapper eliminating scattered ``getattr(config, ...)`` in wrappers."""

    __slots__ = ("_cfg",)
    _cfg: Union[interop_pb2.TlsConfig, SimpleNamespace]

    def __init__(self, cfg: TlsConfigInput) -> None:
        if isinstance(cfg, TlsConfigView):
            self._cfg = cfg._cfg
        else:
            self._cfg = cfg

    @property
    def raw(self) -> Union[interop_pb2.TlsConfig, SimpleNamespace]:
        return self._cfg

    @property
    def version(self) -> str:
        return (self._cfg.version or "").strip()

    @property
    def cipher_suite(self) -> str:
        return (self._cfg.cipher_suite or "").strip()

    @property
    def server_hostname(self) -> str:
        return (self._cfg.server_hostname or "").strip()

    @property
    def port(self) -> int:
        return int(self._cfg.port or 0)

    @property
    def expect_hrr(self) -> bool:
        return bool(self._cfg.expect_hrr)

    @property
    def session_tickets_enabled(self) -> bool:
        return bool(self._cfg.session_tickets_enabled)

    @property
    def resumption_step(self) -> str:
        return (self._cfg.resumption_step or "").strip()

    @property
    def repo_root(self) -> str:
        return (self._cfg.repo_root or "").strip()

    @property
    def ca_file(self) -> str:
        return (self._cfg.ca_file or "").strip()

    @property
    def certificate(self) -> bytes:
        return getattr(self._cfg, "certificate", None) or b""

    @property
    def private_key(self) -> bytes:
        return getattr(self._cfg, "private_key", None) or b""

    def list_field(self, name: str) -> list[str]:
        raw = getattr(self._cfg, name, None) or []
        out: list[str] = []
        for item in raw:
            text = str(item).strip()
            if text:
                out.append(text)
        return out

    @property
    def alpn_protocols(self) -> list[str]:
        return self.list_field("alpn_protocols")

    @property
    def supported_groups(self) -> list[str]:
        return self.list_field("supported_groups")

    @property
    def signature_schemes(self) -> list[str]:
        return self.list_field("signature_schemes")

    @property
    def psk_modes(self) -> list[str]:
        return self.list_field("psk_modes")

    def has_inline_identity_pem(self) -> bool:
        return bool(self.certificate.strip() and self.private_key.strip())


TlsConfigLike: TypeAlias = Union[interop_pb2.TlsConfig, TlsConfigView]
"""Protobuf config or an existing view (wrappers, driver, identity)."""

TlsConfigInput: TypeAlias = Union[TlsConfigLike, SimpleNamespace]
"""Config-like object from gRPC or CLI ``run_args_tls_config_view``."""

RoleLike: TypeAlias = Union[int, interop_pb2.Role]
"""``interop_pb2.SERVER`` / ``interop_pb2.CLIENT`` (or ``ROLE_UNSPECIFIED``)."""
