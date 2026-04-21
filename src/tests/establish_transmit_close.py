"""TLS 1.3 happy path: establish, transmit, verify echo."""


def run(driver, tls_hostname):
    """Establish TLS 1.3, transmit, verify. Expect SUCCESS."""
    try:
        return driver._run_establish_transmit(
            driver._default_config(tls_hostname, "1.3"),
            "establish → transmit → close (TLS 1.3)",
        )
    finally:
        driver._cleanup()
