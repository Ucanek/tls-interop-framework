#!/usr/bin/env python3
"""
Read deploy/wrappers.json for matrix pairs and wrapper name validation.

If ``matrix_pairs`` is absent or empty, pairs are the Cartesian product of
``wrappers`` (each with each). If ``matrix_pairs`` is a non-empty array, only
those [server, client] rows are used.

Usage:
  python3 scripts/matrix_config.py pairs [CONFIG_PATH]
  python3 scripts/matrix_config.py valid <name> [CONFIG_PATH]

CONFIG_PATH defaults to deploy/wrappers.json under the repository root
(parent of scripts/).
"""
import json
import os
import sys


def _default_config_path():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "deploy", "wrappers.json")


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def known_wrappers(data):
    return frozenset(data.get("wrappers") or ())


def matrix_pairs(data):
    explicit = data.get("matrix_pairs")
    if explicit:
        return [tuple(p) for p in explicit]
    w = list(data.get("wrappers") or [])
    return [(a, b) for a in w for b in w]


def cmd_pairs(path):
    for a, b in matrix_pairs(load_config(path)):
        print(f"{a} {b}")


def cmd_valid(path, name):
    data = load_config(path)
    ok = name in known_wrappers(data) and name in (data.get("launch") or {})
    sys.exit(0 if ok else 1)


def main():
    argv = sys.argv[1:]
    if not argv:
        print("usage: matrix_config.py pairs|valid …", file=sys.stderr)
        sys.exit(2)
    cmd = argv.pop(0)
    if cmd == "pairs":
        path = argv[0] if argv else _default_config_path()
        cmd_pairs(path)
        return
    if cmd == "valid":
        if not argv:
            print("usage: matrix_config.py valid <name> [CONFIG]", file=sys.stderr)
            sys.exit(2)
        name = argv.pop(0)
        path = argv[0] if argv else _default_config_path()
        cmd_valid(path, name)
        return
    print("unknown command", cmd, file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
