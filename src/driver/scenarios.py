"""
TLS interop scenario registry.

Each row: scenario id, TLS ``version`` string used for GetMetadata/capability
filtering (see driver ``_tls_config_version_to_capability_name``), and a
callable ``run(driver, tls_hostname)`` implemented under ``src/tests/``.
"""

from tests import establish_transmit_close as m_establish_13
from tests import establish_transmit_close_tls12 as m_establish_12
from tests import expect_failure_wrong_hostname as m_wrong_host
from tests import expect_failure_wrong_port as m_wrong_port

# (scenario_id, tls_version_requirement, run_callable)
SCENARIO_REGISTRY = [
    ("establish_transmit_close", "1.3", m_establish_13.run),
    ("establish_transmit_close_tls12", "1.2", m_establish_12.run),
    ("expect_failure_wrong_hostname", "1.3", m_wrong_host.run),
    ("expect_failure_wrong_port", "1.3", m_wrong_port.run),
]

SCENARIO_TLS_REQUIREMENT = {name: ver for name, ver, _ in SCENARIO_REGISTRY}

ORDERED_SCENARIO_IDS = tuple(name for name, _, _ in SCENARIO_REGISTRY)

ARGPARSE_SCENARIO_CHOICES = ["all", *ORDERED_SCENARIO_IDS]
