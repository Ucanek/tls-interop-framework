"""Parallel worker slot pool for isolated wrapper subprocess sets."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

import logging

from core.orchestration_context import (
    orchestration_context_for_backends,
    set_orchestration_context,
)
from core.session_manager import WorkerSlotSession, _WORKER_PORT_STRIDE

logger = logging.getLogger(__name__)


class WorkerSlotPool:
    """Pool of ``WorkerSlotSession`` instances (one isolated wrapper set per slot)."""

    def __init__(
        self,
        repo: Path,
        backends: frozenset[str],
        num_slots: int,
        *,
        verbose: bool = False,
        grpc_base_overrides: Mapping[str, int] | None = None,
    ) -> None:
        if num_slots < 1:
            raise ValueError("num_slots must be >= 1")
        self.repo = repo.resolve()
        self.backends = frozenset(backends)
        self.verbose = verbose
        self._sessions = [
            WorkerSlotSession(
                self.repo,
                self.backends,
                slot_id=i,
                verbose=verbose,
                grpc_port_overrides=grpc_base_overrides,
            )
            for i in range(num_slots)
        ]

    def session(self, slot_id: int) -> WorkerSlotSession:
        return self._sessions[int(slot_id)]

    def start(self) -> None:
        set_orchestration_context(orchestration_context_for_backends(self.backends))
        for session in self._sessions:
            session.start()
        if self.verbose:
            logger.debug(
                "Parallel workers: %d slot(s), port stride %d",
                len(self._sessions),
                _WORKER_PORT_STRIDE,
            )

    def stop(self) -> None:
        for session in self._sessions:
            session.stop(clear_context=False)
        set_orchestration_context(None)

    def __enter__(self) -> WorkerSlotPool:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()
