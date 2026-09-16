"""Python shim that drives the Rust ``vgi-rpc-client`` for conformance.

Everything that used to live here is now the port-agnostic
``vgi_rpc.conformance.client_driver`` in the Python reference, and the control
protocol it speaks is written down in that repo's
``tools/cross-port/specs/CLIENT_DRIVER_PROTOCOL.md``.  What is left is the only
genuinely Rust-shaped part: where this repository's driver binary lives.

The names below are kept because ``test_rust_conformance.py`` — which the C#
port also runs, substituting its own ``VGI_CLIENT_DRIVER`` — imports them.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from vgi_rpc.conformance.client_driver import ClientDriver, ClientDriverProxy
from vgi_rpc.external import ExternalLocationConfig
from vgi_rpc.log import Message

# ``VGI_CLIENT_DRIVER`` wins when set (every CI leg sets it, and the C# port
# points it at its own driver); this is the developer-machine fallback.
_DEFAULT_DRIVER = str(Path(__file__).parent / "target" / "debug" / "vgi-rpc-conformance-client-driver")

DRIVER = ClientDriver.from_env(default=[_DEFAULT_DRIVER])


def RustClientProxy(  # noqa: N802 - kept as a class-like name for the harness
    transport: str,
    target: object,
    on_log: Callable[[Message], None] | None = None,
    *,
    external_config: ExternalLocationConfig | None = None,
    compression_level: int | None = 1,
    headers: Mapping[str, str] | None = None,
) -> ClientDriverProxy:
    """Open one driver-backed connection; mirrors the old constructor."""
    return DRIVER.connect(
        transport,
        target,
        on_log,
        external_config=external_config,
        compression_level=compression_level,
        headers=headers,
    )


rust_http_connect = DRIVER.http_connect
rust_http_capabilities = DRIVER.http_capabilities
rust_request_upload_urls = DRIVER.request_upload_urls
rust_http_introspect = DRIVER.http_introspect
