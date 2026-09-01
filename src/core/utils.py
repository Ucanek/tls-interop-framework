"""Shared string normalization and CSV/asymmetric parsing helpers."""

from __future__ import annotations


def norm_token(s: str) -> str:
    """Fold catalog/native tokens for loose equality (hyphens and underscores removed)."""
    return (s or "").strip().lower().replace("-", "").replace("_", "")


def norm_catalog_token(raw: str) -> str:
    """Normalize catalog id tokens (lowercase, spaces removed)."""
    return (raw or "").strip().lower().replace(" ", "")


def norm_scheme_token(raw: str) -> str:
    """Normalize TLS signature scheme tokens (lowercase, spaces→removed, underscores→hyphens)."""
    return (raw or "").strip().lower().replace(" ", "").replace("_", "-")


def split_csv_tokens(part: str) -> list[str]:
    """Comma-separated tokens (empty segments dropped)."""
    return [p.strip() for p in (part or "").split(",") if p.strip()]


def split_asymmetric_csv(val: str | None) -> tuple[list[str], list[str]]:
    """
    Split comma-separated tokens per role on the first ``:`` in the raw string.

    With no colon, both sides receive the same parsed list.
    """
    whole = (val or "").strip()
    if not whole:
        return [], []
    if ":" in whole:
        left, right = whole.split(":", 1)
        return ([p.strip() for p in left.split(",") if p.strip()],
            [p.strip() for p in right.split(",") if p.strip()])
    parts = [p.strip() for p in whole.split(",") if p.strip()]
    return parts, parts


def parse_asymmetric(val: str | None) -> tuple[str, str]:
    v = (val or "").strip()
    if ":" in v:
        left, right = v.split(":", 1)
        return left.strip(), right.strip()
    return v, v


def asymmetric_role_part(val: str | None, *, server: bool) -> str:
    """Server (left) or client (right) segment from a symmetric or ``server:client`` value."""
    left, right = parse_asymmetric(val)
    return left if server else right
