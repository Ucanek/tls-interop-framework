"""
TLS interop scenario registry.

Each row: scenario id, TLS ``version`` string used for GetMetadata/capability
filtering (see driver ``_tls_config_version_to_capability_name``), and the
``InteropDriver`` method name invoked for that scenario.
"""

# (scenario_id, tls_version_requirement, InteropDriver method name)
SCENARIO_REGISTRY = [
    ("establish_transmit_close", "1.3", "run_establish_transmit_close"),
    ("establish_transmit_close_tls12", "1.2", "run_establish_transmit_close_tls12"),
    ("expect_failure_wrong_hostname", "1.3", "run_expect_failure_wrong_hostname"),
    ("expect_failure_wrong_port", "1.3", "run_expect_failure_wrong_port"),
]

SCENARIO_TLS_REQUIREMENT = {name: ver for name, ver, _ in SCENARIO_REGISTRY}

ORDERED_SCENARIO_IDS = tuple(name for name, _, _ in SCENARIO_REGISTRY)

ARGPARSE_SCENARIO_CHOICES = ["all", *ORDERED_SCENARIO_IDS]
