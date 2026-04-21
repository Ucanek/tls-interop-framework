"""
TLS interoperability scenario implementations (one module per scenario).

Each module exposes ``run(driver, tls_hostname) -> bool`` where ``driver`` is
``InteropDriver``. Shared multi-step flows live on ``InteropDriver`` (e.g.
``_run_establish_transmit``). Register new scenarios in ``src/driver/scenarios.py``.
"""
