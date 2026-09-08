"""Orchestration overrides read once at driver startup (not from ``os.environ`` in helpers)."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class OrchestrationContext:
    """Env-driven matrix overrides propagated into identity and wrapper subprocess env."""

    server_signature_schemes: str = ""
    asymmetric_signature_schemes: str = ""
    gnutls_nss_pair: bool = False


_current: OrchestrationContext | None = None


def orchestration_context_from_environ() -> OrchestrationContext:
    pair_raw = (os.environ.get("INTEROP_GNUTLS_NSS_PAIR") or "0").strip().lower()
    return OrchestrationContext(
        server_signature_schemes=(os.environ.get("INTEROP_SERVER_SIGNATURE_SCHEMES") or "").strip(),
        asymmetric_signature_schemes=(os.environ.get("INTEROP_SIGNATURE_SCHEMES") or "").strip(),
        gnutls_nss_pair=pair_raw in frozenset({"1", "true", "yes", "on"}),
    )


def set_orchestration_context(ctx: OrchestrationContext | None) -> None:
    global _current
    _current = ctx


def active_orchestration_context() -> OrchestrationContext:
    return _current if _current is not None else OrchestrationContext()


def orchestration_context_for_backends(backends: Iterable[str]) -> OrchestrationContext:
    """Merge CLI/env overrides with wrapper ``orchestration_env`` hook values."""
    from core.registry import merged_orchestration_env

    base = orchestration_context_from_environ()
    merged = merged_orchestration_env(backends)
    pair_env = (merged.get("INTEROP_GNUTLS_NSS_PAIR") or "").strip().lower()
    pair = base.gnutls_nss_pair or pair_env in frozenset({"1", "true", "yes", "on"})
    return OrchestrationContext(
        server_signature_schemes=base.server_signature_schemes,
        asymmetric_signature_schemes=base.asymmetric_signature_schemes,
        gnutls_nss_pair=pair,
    )
