#!/usr/bin/env python3
"""Primary and only supported CLI entrypoint for TLS interop runs."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

MULTI_VALUE_OPTION_IDS = {
    "supported_groups",
    "signature_schemes",
    "signature_schemes_cert",
    "alpn_protocols",
    "supported_versions",
    "psk_modes",
    "certificate_compression_send",
    "certificate_compression_receive",
}

NON_TLS_OPTION_IDS = {"server_wrapper", "client_wrapper"}

PREVIEW_ONLY_OPTION_IDS = MULTI_VALUE_OPTION_IDS | (
    {
        "min_tls_version",
        "max_tls_version",
        "ticket_cipher",
        "ticket_lifetime",
        "max_early_data",
        "enable_early_data",
        "prefer_server_ciphers",
        "use_encrypt_then_mac",
        "use_extended_master_secret",
        "require_extended_master_secret",
        "record_size_limit",
        "max_fragment_length",
        "session_tickets_enabled",
        "ocsp_stapling",
        "renegotiation",
        "post_handshake_auth",
        "verify_peer",
        "verify_hostname",
        "ca_file",
        "ca_path",
        "keylog_file",
        "certificate_pem",
        "private_key_pem",
    }
)


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_json(path: str) -> dict:
    if not os.path.isfile(path):
        raise ValueError(f"Config file not found: {path}")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Config file must contain a JSON object: {path}")
    return data


def _default_wrappers_path() -> str:
    return os.path.join(_repo_root(), "deploy", "wrappers.json")


def _default_options_path() -> str:
    return os.path.join(_repo_root(), "deploy", "tls_options.json")


def _known_wrappers(path: str) -> list[str]:
    wrappers = _read_json(path).get("wrappers") or []
    if not isinstance(wrappers, list) or not all(isinstance(x, str) for x in wrappers):
        raise ValueError(f"Invalid wrappers list in {path}")
    if not wrappers:
        raise ValueError(f"No wrappers configured in {path}")
    return list(wrappers)


def _choices_for_option(path: str, option_id: str) -> list[str]:
    options = _read_json(path).get("options") or []
    if not isinstance(options, list):
        raise ValueError(f"Invalid options list in {path}")
    for item in options:
        if isinstance(item, dict) and item.get("id") == option_id:
            choices = item.get("choices") or []
            if not isinstance(choices, list) or not all(
                isinstance(x, str) for x in choices
            ):
                raise ValueError(f"Invalid choices for option '{option_id}' in {path}")
            return list(choices)
    return []


def _options_catalog(path: str) -> list[dict]:
    options = _read_json(path).get("options") or []
    if not isinstance(options, list):
        raise ValueError(f"Invalid options list in {path}")
    ids: set[str] = set()
    out: list[dict] = []
    for item in options:
        if not isinstance(item, dict):
            raise ValueError(f"Each option item must be a JSON object in {path}")
        option_id = item.get("id")
        if not isinstance(option_id, str) or not option_id:
            raise ValueError(f"Each option must define non-empty string 'id' in {path}")
        if option_id in ids:
            raise ValueError(f"Duplicate option id '{option_id}' in {path}")
        ids.add(option_id)
        choices = item.get("choices")
        if choices is not None and (
            not isinstance(choices, list) or not all(isinstance(x, str) for x in choices)
        ):
            raise ValueError(f"Invalid choices for option '{option_id}' in {path}")
        out.append(item)
    return out


def _print_options(path: str) -> None:
    for item in _options_catalog(path):
        choices = item.get("choices") or []
        ctext = f" choices={choices}" if choices else ""
        print(f"{item.get('id')}{ctext}")


def _parse_csv_values(raw: str, arg_name: str) -> list[str]:
    if not raw:
        return []
    values = [part.strip() for part in raw.split(",")]
    if any(not v for v in values):
        raise ValueError(
            f"{arg_name} must be a comma-separated list of non-empty values"
        )
    return values


def _validate_args(args: argparse.Namespace, wrappers_path: str, options_path: str) -> None:
    if args.list_wrappers and args.list_options:
        raise ValueError("Use only one of --list-wrappers or --list-options")

    wrappers = set(_known_wrappers(wrappers_path))
    if args.server not in wrappers:
        raise ValueError(f"Unknown --server '{args.server}'. Known: {sorted(wrappers)}")
    if args.client not in wrappers:
        raise ValueError(f"Unknown --client '{args.client}'. Known: {sorted(wrappers)}")

    version_choices = _choices_for_option(options_path, "tls_version")
    if args.tls_version and args.tls_version not in version_choices:
        raise ValueError(f"--tls-version must be one of: {', '.join(version_choices)}")

    cipher_choices = _choices_for_option(options_path, "cipher_suite")
    if args.cipher_suite and args.cipher_suite not in cipher_choices:
        raise ValueError(f"--cipher-suite must be one of: {', '.join(cipher_choices)}")

    if not (0 <= args.tls_port <= 65535):
        raise ValueError("--tls-port must be in range 0..65535")

    if args.tls_hostname:
        if args.tls_hostname.strip() != args.tls_hostname:
            raise ValueError("--tls-hostname must not have leading/trailing spaces")
        if any(ch.isspace() for ch in args.tls_hostname):
            raise ValueError("--tls-hostname must not contain whitespace")
        _validate_hostname(args.tls_hostname)
    preview_used: list[str] = []
    for item in _options_catalog(options_path):
        option_id = item["id"]
        if option_id in NON_TLS_OPTION_IDS:
            continue
        value = getattr(args, option_id)

        # Already validated above with dedicated logic.
        if option_id in {"tls_version", "cipher_suite", "tls_port", "tls_hostname"}:
            if value not in ("", 0):
                pass
            continue

        if not value:
            continue

        arg_name = f"--{option_id.replace('_', '-')}"
        choices = item.get("choices") or []

        if option_id in MULTI_VALUE_OPTION_IDS:
            values = _parse_csv_values(value, arg_name)
            setattr(args, f"{option_id}_values", values)
            if choices:
                unknown = sorted(v for v in values if v not in choices)
                if unknown:
                    raise ValueError(
                        f"{arg_name} unknown value(s): {', '.join(unknown)}. "
                        f"Known: {', '.join(choices)}"
                    )
        elif choices and value not in choices:
            raise ValueError(f"{arg_name} must be one of: {', '.join(choices)}")

        if option_id == "alpn_protocols":
            alpn_values = getattr(args, "alpn_protocols_values")
            alpn_re = re.compile(r"^[A-Za-z0-9._/+:-]{1,255}$")
            invalid_alpn = sorted(v for v in alpn_values if not alpn_re.fullmatch(v))
            if invalid_alpn:
                raise ValueError(
                    "--alpn-protocols contains invalid token(s): "
                    f"{', '.join(invalid_alpn)}"
                )

        if option_id in PREVIEW_ONLY_OPTION_IDS:
            preview_used.append(option_id)

    args.preview_option_ids = preview_used


def _validate_hostname(hostname: str) -> None:
    # Allow IPv4 literals.
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
        parts = [int(x) for x in hostname.split(".")]
        if all(0 <= p <= 255 for p in parts):
            return
        raise ValueError("--tls-hostname IPv4 octets must be in range 0..255")

    # RFC-ish hostname validation for DNS names.
    if len(hostname) > 253:
        raise ValueError("--tls-hostname must be <= 253 characters")
    labels = hostname.split(".")
    if any(not label for label in labels):
        raise ValueError("--tls-hostname must not contain empty labels")
    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    for label in labels:
        if not label_re.fullmatch(label):
            raise ValueError(
                "--tls-hostname must be a valid DNS name label sequence (RFC-style)"
            )


def _compose_run(args: argparse.Namespace) -> int:
    root = _repo_root()
    matrix = os.path.join(root, "deploy", "compose.yaml")
    wrappers_path = _default_wrappers_path()
    project = f"interop-{args.server}-{args.client}"
    env = os.environ.copy()
    env["WRAPPERS_CONFIG"] = wrappers_path
    env["SERVER_WRAPPER"] = args.server
    env["CLIENT_WRAPPER"] = args.client
    env["INTEROP_GNUTLS_NSS_PAIR"] = (
        "1" if args.server == "gnutls" and args.client == "nss" else "0"
    )
    env["INTEROP_SCENARIO"] = "all"
    env["INTEROP_TLS_VERSION"] = args.tls_version
    env["INTEROP_CIPHER_SUITE"] = args.cipher_suite
    env["INTEROP_TLS_PORT"] = str(args.tls_port)
    env["INTEROP_TLS_HOSTNAME"] = args.tls_hostname
    env["INTEROP_VERBOSE"] = "1" if args.verbose else "0"

    compose = ["docker", "compose", "-p", project, "-f", matrix]
    down = compose + ["down", "--remove-orphans"]
    build = compose + ["build"] + ([] if args.verbose else ["-q"])
    run = compose + ["run", "--rm", "-T", "driver"]

    print(f"========== {args.server}x{args.client} ==========")
    if args.preview_option_ids:
        used = ", ".join(sorted(f"--{x.replace('_', '-')}" for x in args.preview_option_ids))
        print(
            f"NOTE: {used} {'are' if len(args.preview_option_ids) > 1 else 'is'} "
            "preview-only and currently used for validation only."
        )
    if args.dry_run:
        print("DRY-RUN compose commands:")
        print(" ".join(down))
        print(" ".join(build))
        print(" ".join(run))
        return 0

    subprocess.run(down, cwd=root, env=env, stdin=subprocess.DEVNULL, check=False)
    rc = 1
    try:
        subprocess.run(build, cwd=root, env=env, stdin=subprocess.DEVNULL, check=True)
        subprocess.run(run, cwd=root, env=env, stdin=subprocess.DEVNULL, check=True)
        rc = 0
    except subprocess.CalledProcessError:
        rc = 1
    finally:
        subprocess.run(down, cwd=root, env=env, stdin=subprocess.DEVNULL, check=False)
    return rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TLS interop runner (single entrypoint). Runs all supported scenarios."
    )
    list_group = parser.add_mutually_exclusive_group()
    list_group.add_argument(
        "--list-wrappers",
        action="store_true",
        help="Print available wrapper implementations and exit",
    )
    list_group.add_argument(
        "--list-options",
        action="store_true",
        help="Print configurable TLS options and exit",
    )
    parser.add_argument("--server", default="openssl", help="Server wrapper implementation")
    parser.add_argument("--client", default="openssl", help="Client wrapper implementation")
    parser.add_argument("--tls-version", default="", help="Override TlsConfig.version")
    parser.add_argument("--cipher-suite", default="", help="Override TlsConfig.cipher_suite")
    parser.add_argument("--tls-port", type=int, default=0, help="Override TlsConfig.port")
    parser.add_argument(
        "--tls-hostname",
        default="",
        help="Override TlsConfig.server_hostname (SNI hostname)",
    )
    parser.add_argument(
        "--supported-groups",
        default="",
        help="Preview-only: comma-separated supported groups (validate-only)",
    )
    parser.add_argument(
        "--alpn-protocols",
        default="",
        help="Preview-only: comma-separated ALPN protocols (validate-only)",
    )
    for item in _options_catalog(_default_options_path()):
        option_id = item["id"]
        if option_id in (
            {"tls_version", "cipher_suite", "tls_port", "tls_hostname"}
            | NON_TLS_OPTION_IDS
            | {"supported_groups", "alpn_protocols"}
        ):
            continue
        cli_name = f"--{option_id.replace('_', '-')}"
        parser.add_argument(
            cli_name,
            default="",
            help="Preview-only option from deploy/tls_options.json (validate-only)",
        )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print compose commands instead of running them",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    wrappers_path = _default_wrappers_path()
    options_path = _default_options_path()
    try:
        if args.list_wrappers:
            for name in _known_wrappers(wrappers_path):
                print(name)
            return 0
        if args.list_options:
            _print_options(options_path)
            return 0
        _validate_args(args, wrappers_path, options_path)
        return _compose_run(args)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
