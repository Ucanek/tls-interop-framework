"""TLS 1.2 happy path: establish, transmit, verify echo."""


def run(driver, tls_hostname):
    """Same as happy path but TLS 1.2 only. Expect SUCCESS."""
    try:
        return driver._run_establish_transmit(
            driver._default_config(tls_hostname, "1.2"),
            "establish → transmit → close (TLS 1.2)",
        )
    finally:
        driver._cleanup()
