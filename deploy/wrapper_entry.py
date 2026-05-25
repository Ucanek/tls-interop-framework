#!/usr/bin/env python3
"""Launch ``wrappers.<WRAPPER>.wrapper`` from ``WRAPPER`` env (e.g. openssl)."""

from __future__ import annotations

import os
import re
import runpy
import sys


_MAIN_DIR = os.path.dirname(os.path.abspath(__file__))
_WRAPPER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def main() -> None:
    raw = (os.environ.get("WRAPPER") or "openssl").strip().lower()
    if not _WRAPPER_RE.fullmatch(raw):
        print(
            f"wrapper_entry: invalid WRAPPER={raw!r} (allowed: {_WRAPPER_RE.pattern})",
            file=sys.stderr,
        )
        sys.exit(1)
    pkg_root = _MAIN_DIR
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    module = f"wrappers.{raw}.wrapper"
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    except ModuleNotFoundError:
        legacy = os.path.join(_MAIN_DIR, f"wrapper_{raw}.py")
        if os.path.isfile(legacy):
            runpy.run_path(legacy, run_name="__main__")
            return
        print(
            f"wrapper_entry: module not found for WRAPPER={raw!r}: {module}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
