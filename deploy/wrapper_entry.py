#!/usr/bin/env python3
"""Launch ``wrappers.<WRAPPER>.wrapper`` from ``WRAPPER`` env (e.g. openssl)."""

from __future__ import annotations

import os
import re
import runpy
import sys


def main() -> None:
    main_dir = os.path.dirname(os.path.abspath(__file__))
    wrapper_re = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
    raw = (os.environ.get("WRAPPER") or "openssl").strip().lower()
    if not wrapper_re.fullmatch(raw):
        print(f"wrapper_entry: invalid WRAPPER={raw!r} (allowed: {wrapper_re.pattern})", file=sys.stderr)
        sys.exit(1)
    pkg_root = main_dir
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    module = f"wrappers.{raw}.wrapper"
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    except ModuleNotFoundError:
        print(f"wrapper_entry: module not found for WRAPPER={raw!r}: {module}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
