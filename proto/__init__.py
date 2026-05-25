"""Generated ``interop`` protobuf/gRPC modules (repo ``proto/`` package)."""

from __future__ import annotations

from core.catalog import ensure_import_paths

ensure_import_paths()

from . import interop_pb2
from . import interop_pb2_grpc

__all__ = ["interop_pb2", "interop_pb2_grpc"]
