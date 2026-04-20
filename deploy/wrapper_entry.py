#!/usr/bin/env python3
"""Resolve WRAPPER env to a wrapper Python script (see deploy/wrappers.json)."""
import json
import os
import sys


def _config_path():
    p = os.environ.get("WRAPPERS_CONFIG")
    if p and os.path.isfile(p):
        return p
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "wrappers.json")


def main():
    path = _config_path()
    if not os.path.isfile(path):
        print(f"wrapper_entry: missing config {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    name = (os.environ.get("WRAPPER") or "openssl").strip()
    launch = cfg.get("launch") or {}
    script = launch.get(name)
    if not script:
        print(f"wrapper_entry: unknown WRAPPER={name!r}", file=sys.stderr)
        sys.exit(1)
    base = os.path.dirname(os.path.abspath(__file__))
    target = script if os.path.isabs(script) else os.path.join(base, script)
    if not os.path.isfile(target):
        print(f"wrapper_entry: script not found: {target}", file=sys.stderr)
        sys.exit(1)
    os.execv(sys.executable, [sys.executable, target])


if __name__ == "__main__":
    main()
