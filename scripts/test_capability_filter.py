#!/usr/bin/env python3
"""
Unit checks for the driver capability filter (phase 2.3).

Run from repository root (after protoc + pip install grpcio/grpcio-tools/protobuf):

  ./scripts/run.sh capability-test
  # or: python3 scripts/test_capability_filter.py
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

_SPEC = importlib.util.spec_from_file_location(
    "interop_driver", os.path.join(ROOT, "src", "driver", "driver.py")
)
_driver = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_driver)

interop_pb2 = __import__("interop_pb2")

InteropDriver = _driver.InteropDriver
_tls = _driver._tls_config_version_to_capability_name


def _meta(name, versions, roles):
    return interop_pb2.LibraryMetadata(
        component_name=name,
        version="0",
        roles=list(roles),
        supported_versions=[
            interop_pb2.Capability(name=n, flags=[interop_pb2.NEGOTIATE]) for n in versions
        ],
    )


def main():
    assert _tls("1.2") == "TLS1.2"
    assert _tls("1.3") == "TLS1.3"
    assert _tls("") == "TLS1.3"

    d = InteropDriver("localhost:1", "localhost:2")
    ok = _meta("S", ["TLS1.2", "TLS1.3"], [interop_pb2.CLIENT, interop_pb2.SERVER])
    d.server_metadata = ok
    d.client_metadata = ok
    assert d.scenario_skip_reason("establish_transmit_close") is None
    assert d.scenario_skip_reason("establish_transmit_close_tls12") is None

    d.client_metadata = _meta("Weak", ["TLS1.2"], [interop_pb2.CLIENT, interop_pb2.SERVER])
    r = d.scenario_skip_reason("establish_transmit_close")
    assert r and "Weak" in r and "TLS1.3" in r
    assert d.scenario_skip_reason("establish_transmit_close_tls12") is None

    d.client_metadata = _meta("Tls13Only", ["TLS1.3"], [interop_pb2.CLIENT, interop_pb2.SERVER])
    d.server_metadata = ok
    r = d.scenario_skip_reason("establish_transmit_close_tls12")
    assert r and "Tls13Only" in r and "TLS1.2" in r

    d.server_metadata = _meta("Srv", [], [interop_pb2.CLIENT])
    d.client_metadata = ok
    r = d.scenario_skip_reason("establish_transmit_close")
    assert r and "server" in r.lower()

    print("capability filter self-check: OK")


if __name__ == "__main__":
    main()
