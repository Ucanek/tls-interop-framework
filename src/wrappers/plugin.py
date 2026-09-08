"""Typing contracts for wrapper plugin classes (``WRAPPER_CLASS`` exports)."""

from __future__ import annotations

from typing import Any, Protocol

from core.registry import TranslationResult
from core.tls_config_view import RoleLike, TlsConfigLike


class WrapperPlugin(Protocol):
    """``BaseTemplateWrapper`` subclass exported as ``WRAPPER_CLASS``."""

    CAPABILITIES: dict[str, Any]

    def __call__(self) -> Any: ...

    def tls_argv_for_config(
        self, config: TlsConfigLike, *, role: RoleLike | None = None,
        capabilities: dict[str, Any] | None = None,
    ) -> TranslationResult: ...

    def local_cli_requirements(self) -> tuple[str, ...]: ...

    def resolve_cli_tool(self, exe: str) -> str | None: ...

    def orchestration_env(self, active_backends: frozenset[str] | set[str]) -> dict[str, str]: ...

    def local_wrapper_env(self, repo: Any, backend_id: str,
        active_backends: frozenset[str] | set[str]) -> dict[str, str]: ...


class WrapperServicerFactory(Protocol):
    """Factory for standalone ``python -m wrappers.<id>.wrapper`` entry points."""

    def __call__(self) -> Any: ...
