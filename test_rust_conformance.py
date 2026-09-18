"""Run Python conformance tests against the Rust conformance worker."""
import contextlib
import os
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol

try:
    import httpx
except ModuleNotFoundError:  # the Python reference moved to the httpx2 fork
    import httpx2 as httpx
import pytest

from vgi_rpc.conformance import ConformanceService
from vgi_rpc.http import http_connect
from vgi_rpc.log import Message
from vgi_rpc.rpc import (
    SubprocessTransport,
    TcpTransport,
    UnixTransport,
    _RpcProxy,
    tcp_connect,
    unix_connect,
)

RUST_WORKER = os.environ.get(
    "RUST_CONFORMANCE_WORKER",
    str(Path(__file__).parent / "conformance-worker-rust"),
)

# "server" (default): Python client drives the Rust server (legacy behavior).
# "client": the Rust vgi-rpc-client drives the server, via a Python shim that
# forwards to the Rust conformance client-driver subprocess.
ROLE = os.environ.get("VGI_CONFORMANCE_ROLE", "server")

# Which conformance SERVER the worker binary speaks. The binary path is
# RUST_CONFORMANCE_WORKER regardless (conf.py points it at the python CLI / go
# binary for cross-language runs); only the CLI flags differ per language.
SERVER = os.environ.get("VGI_CONFORMANCE_SERVER", "rust")


def _worker_cmd(mode: str, path: str | None = None) -> list[str]:
    """Build the argv to spawn the conformance server in `mode`.

    mode ∈ {"stdio", "http", "unix", "tcp"}. The Rust and Go workers default
    describe-on; the Python CLI needs an explicit ``--describe`` and an
    explicit ``--pipe`` for stdio.
    """
    base = [RUST_WORKER]
    if SERVER == "python":
        extra = ["--describe"]
        if mode == "stdio":
            return base + ["--pipe", *extra]
        if mode == "http":
            return base + ["--http", *extra]
        if mode == "unix":
            return base + ["--unix", path, *extra]
        if mode == "tcp":
            return base + ["--tcp", path, *extra]
    else:  # rust / go share the same flag surface
        if mode == "stdio":
            return base
        if mode == "http":
            return base + ["--http"]
        if mode == "unix":
            return base + ["--unix", path]
        if mode == "tcp":
            return base + ["--tcp", path]
    raise AssertionError(f"unknown worker mode {mode!r}")


# --- Python reference HTTP servers (full-featured: sticky, storage, strict,
# auth) used when SERVER=python so the Rust client's external/sticky/413/strict
# paths validate against the canonical Python implementation. -----------------
# The canonical reference is the `vgi-rpc-python` checkout. `~/Development/
# vgi-rpc` is `main` — numerically a higher version, but with none of the
# multiservice work (no routing key, flat routes, `__describe__` still live),
# so a run pinned there fails every namespaced call and blames the port.
#   VGI_RPC_PYTHON_REPO  checkout root of vgi-rpc-python
#   VGI_RPC_PYTHON       interpreter that has that checkout importable
_REF_REPO = Path(
    os.environ.get("VGI_RPC_PYTHON_REPO")
    or Path.home() / "Development" / "vgi-rpc-python"
)
_VENV_PY = os.environ.get("VGI_RPC_PYTHON") or str(_REF_REPO / ".venv" / "bin" / "python")
# Directory holding the Python reference serve_conformance_*.py scripts. These
# live in the vgi-rpc-python *repo* (not the PyPI wheel), so cross-language
# client runs against the Python server need a checkout of that repo.
_PY_TESTS = Path(os.environ.get("VGI_PY_TESTS_DIR") or _REF_REPO / "tests")
_PY_SERVE_HTTP = str(_PY_TESTS / "serve_conformance_http.py")
_PY_SERVE_STRICT = str(_PY_TESTS / "serve_conformance_http_strict.py")
_PY_SERVE_AUTH = str(_PY_TESTS / "serve_conformance_http_auth.py")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn_read_port(
    args: list[str],
    *,
    expect_port: int | None = None,
    tcp_only_ready: bool = False,
) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    line = proc.stdout.readline().decode().strip()
    assert line.startswith("PORT:"), f"Expected PORT:<n>, got: {line!r} (args={args})"
    port = int(line.split(":", 1)[1])
    if expect_port is not None:
        assert port == expect_port, f"expected PORT:{expect_port}, got {port}"
    if tcp_only_ready:
        _wait_for_tcp("127.0.0.1", port)
    else:
        _wait_for_http(port)
    return proc, port


def _start_rust_http_with_storage(
    storage_url: str | None,
    zstd: bool,
    *,
    externalize_threshold: int | None = None,
    max_request_bytes: int | None = None,
    max_response_bytes: int | None = None,
    max_externalized_response_bytes: int | None = None,
    external_security: bool = False,
) -> tuple[subprocess.Popen, int]:
    args = [RUST_WORKER, "--http-with-storage", storage_url or ""]
    if zstd:
        args.append("--zstd")
    if externalize_threshold is not None:
        args += ["--externalize-threshold", str(externalize_threshold)]
    if max_request_bytes is not None:
        args += ["--max-request-bytes", str(max_request_bytes)]
    if max_response_bytes is not None:
        args += ["--max-response-bytes", str(max_response_bytes)]
    if max_externalized_response_bytes is not None:
        args += [
            "--max-externalized-response-bytes",
            str(max_externalized_response_bytes),
        ]
    if external_security:
        args.append("--external-security")
    return _spawn_read_port(args)


# The externalised-cap fixture's two numbers. Tight external cap, *generous*
# body cap: an externalised payload leaves only a pointer batch on the wire,
# so if the body cap were tight too it would fail first and
# ``TestExternalizedResponseCap`` would pass while proving nothing about the
# external channel. Mirrors the reference's conftest fixture.
_EXT_CAP_MAX_EXTERNALIZED_BYTES = 64 * 1024
_EXT_CAP_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


# Shared AEAD key for the sticky peer pair. Both workers can open each other's
# session tokens, which is the point: the rejection under test has to come from
# the server_id comparison, not from a decrypt failure.
_STICKY_PEER_TOKEN_KEY = "5f" * 32

# The one origin the CORS worker grants. Fixed by the shared suite: TestCors
# preflights with exactly this value, so a worker configured with any other
# would answer every probe with a refusal that reads as "CORS unimplemented".
_CORS_ORIGIN = "https://conformance.example"


def _spawn_http_variant(variant: str, storage_url: str | None = None) -> tuple[subprocess.Popen, int]:
    """Spawn an HTTP conformance server of `variant` for the current SERVER.

    variant ∈ {plain, no_compression, storage, zstd_storage, externalize_always,
    strict, small_request_cap, auth, sticky_short_ttl, sticky_peer_a, sticky_peer_b, sticky_auth,
    cors, identity, identity_introspect_only}.
    Raises ``pytest.skip`` for (server, variant) combinations not wired here
    (the Go conformance binary doesn't expose the storage/strict/auth modes).

    The sticky_* variants back the upstream failure-path fixtures; see the
    reference repo's ``docs/sticky-sessions-spec.md`` §9.1. The two peers share
    one AEAD key so the wrong-worker rejection provably comes from the
    ``server_id`` comparison rather than a decrypt failure — which is why they
    must also report *different* ids.
    """
    if SERVER == "python":
        if variant == "plain":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http"])
        if variant == "no_compression":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http", "--no-compression"])
        if variant == "cold_call_cache":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http", "--no-call-state-cache"])
        if variant == "auth_reason":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_AUTH, "--port", str(_free_port())])
        if variant == "sticky_short_ttl":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http", "--sticky-ttl", "1"])
        if variant in ("sticky_peer_a", "sticky_peer_b"):
            # The reference server mints a random server_id per process, so the
            # two peers differ without an explicit flag.
            return _spawn_read_port(
                [_VENV_PY, _PY_SERVE_HTTP, "--http", "--token-key", _STICKY_PEER_TOKEN_KEY]
            )
        if variant == "sticky_auth":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http", "--sticky-auth"])
        if variant == "cors":
            port = _free_port()
            return _spawn_read_port(
                [
                    _VENV_PY,
                    _PY_SERVE_HTTP,
                    "--port",
                    str(port),
                    "--fake-storage",
                    storage_url or "",
                    "--cors-origin",
                    _CORS_ORIGIN,
                ],
                expect_port=port,
            )
        if variant in ("identity", "identity_introspect_only"):
            mode = "both" if variant == "identity" else "introspect-only"
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http", "--identity", mode])
        if variant in ("storage", "zstd_storage", "externalize_always", "external_security"):
            port = _free_port()
            args = [_VENV_PY, _PY_SERVE_HTTP, "--port", str(port), "--fake-storage", storage_url or ""]
            if variant == "zstd_storage":
                args += ["--compression", "zstd"]
            if variant == "externalize_always":
                args += ["--externalize-threshold", "1", "--max-request-bytes", "1048576"]
            if variant == "external_security":
                args += [
                    "--max-request-bytes",
                    "1048576",
                    "--max-fetch-bytes",
                    "4096",
                    "--max-decompressed-fetch-bytes",
                    "8192",
                    "--reject-localhost-redirects",
                ]
            return _spawn_read_port(args, expect_port=port)
        if variant == "strict":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_STRICT])
        if variant == "small_request_cap":
            port = _free_port()
            return _spawn_read_port(
                [
                    _VENV_PY,
                    _PY_SERVE_HTTP,
                    "--port",
                    str(port),
                    "--max-request-bytes",
                    str(4 * 1024),
                ],
                expect_port=port,
            )
        if variant == "externalized_cap":
            return _spawn_read_port(
                [
                    _VENV_PY,
                    _PY_SERVE_STRICT,
                    "--fake-storage",
                    storage_url or "",
                    "--max-externalized-response-bytes",
                    str(_EXT_CAP_MAX_EXTERNALIZED_BYTES),
                    "--max-response-bytes",
                    str(_EXT_CAP_MAX_RESPONSE_BYTES),
                ]
            )
        if variant == "auth":
            port = _free_port()
            return _spawn_read_port([_VENV_PY, _PY_SERVE_AUTH, "--port", str(port)], expect_port=port)
    elif SERVER == "rust":
        if variant == "plain":
            return _spawn_read_port(_worker_cmd("http"))
        if variant == "no_compression":
            return _spawn_read_port([*_worker_cmd("http"), "--no-compression"])
        if variant == "storage":
            return _start_rust_http_with_storage(storage_url, zstd=False)
        if variant == "zstd_storage":
            return _start_rust_http_with_storage(storage_url, zstd=True)
        if variant == "external_security":
            return _start_rust_http_with_storage(
                storage_url,
                zstd=False,
                max_request_bytes=1024 * 1024,
                external_security=True,
            )
        if variant == "externalize_always":
            return _start_rust_http_with_storage(
                storage_url, zstd=False, externalize_threshold=1, max_request_bytes=1024 * 1024
            )
        if variant == "strict":
            return _spawn_read_port([RUST_WORKER, "--http", "--strict"])
        if variant == "small_request_cap":
            return _spawn_read_port(
                [RUST_WORKER, "--http", "--max-request-bytes", str(4 * 1024)]
            )
        if variant == "externalized_cap":
            # Storage mode, because the cap under test only bites on the
            # external channel. `--externalize-threshold 4096` matches the
            # reference fixture's default so a payload comfortably under the
            # cap still externalizes (that's the group's control case), and
            # the request cap is opened up so the *request* body of an
            # oversized echo isn't what fails.
            return _start_rust_http_with_storage(
                storage_url,
                zstd=False,
                externalize_threshold=4096,
                max_request_bytes=_EXT_CAP_MAX_RESPONSE_BYTES,
                max_response_bytes=_EXT_CAP_MAX_RESPONSE_BYTES,
                max_externalized_response_bytes=_EXT_CAP_MAX_EXTERNALIZED_BYTES,
            )
        if variant == "auth":
            return _spawn_read_port([RUST_WORKER, "--http-auth"])
        if variant == "auth_reason":
            # The reject-all worker already honours X-Conformance-Auth-Reason.
            return _spawn_read_port([RUST_WORKER, "--http-auth"])
        if variant == "cold_call_cache":
            return _spawn_read_port([*_worker_cmd("http"), "--no-call-state-cache"])
        if variant == "sticky_short_ttl":
            return _spawn_read_port([RUST_WORKER, "--http", "--sticky-ttl", "1"])
        if variant in ("sticky_peer_a", "sticky_peer_b"):
            # The Rust worker otherwise hardcodes "rust-conf-0001", so both
            # peers would be the same worker without the explicit --server-id.
            return _spawn_read_port(
                [
                    RUST_WORKER,
                    "--http",
                    "--token-key",
                    _STICKY_PEER_TOKEN_KEY,
                    "--server-id",
                    f"rust-conf-{variant}",
                ]
            )
        if variant == "sticky_auth":
            # NOT --http-auth: that one is reject-all and moves the prefix
            # to /vgi. This is the plain worker plus a principal resolver.
            return _spawn_read_port([RUST_WORKER, "--http", "--sticky-auth"])
        if variant == "cors":
            return _spawn_read_port(
                [
                    RUST_WORKER,
                    "--http-with-storage",
                    storage_url or "",
                    "--cors-origin",
                    _CORS_ORIGIN,
                ]
            )
        if variant in ("identity", "identity_introspect_only"):
            # Same binary, different flag — which is the point: the narrowing
            # under test is a *configuration* difference, so two binaries
            # could not show it.
            mode = "both" if variant == "identity" else "introspect-only"
            return _spawn_read_port([RUST_WORKER, "--http", "--identity", mode])
    else:  # go
        if variant == "plain":
            return _spawn_read_port(_worker_cmd("http"))
        pytest.skip(f"go conformance server doesn't expose HTTP variant {variant!r}")
    raise AssertionError(f"unknown http variant {variant!r} for server {SERVER!r}")


# Under client role, route the HTTP-feature tests (external-location, sticky,
# response-caps) — which import http_connect / http_capabilities /
# request_upload_urls in-body — through the Rust client so they actually
# validate it (instead of silently using the Python http client).
if ROLE == "client":
    import vgi_rpc.http as _vgi_http
    import rust_client_proxy as _shim

    _vgi_http.http_connect = _shim.rust_http_connect  # type: ignore[assignment]
    _vgi_http.http_capabilities = _shim.rust_http_capabilities  # type: ignore[assignment]
    _vgi_http.request_upload_urls = _shim.rust_request_upload_urls  # type: ignore[assignment]


@pytest.fixture(scope="session")
def rust_transport() -> Iterator[SubprocessTransport]:
    transport = SubprocessTransport([RUST_WORKER])
    yield transport
    transport.close()


def _wait_for_http(port: int, timeout: float = 5.0) -> None:
    """Poll until the HTTP server is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _ = httpx.get(f"http://127.0.0.1:{port}/", timeout=5.0)
            return
        except (httpx.ConnectError, httpx.ConnectTimeout):
            time.sleep(0.1)
    raise TimeoutError(f"HTTP server on port {port} did not start within {timeout}s")


def _http_variant_fixture(variant: str, storage_url: str | None = None) -> Iterator[int]:
    proc, port = _spawn_http_variant(variant, storage_url)
    try:
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def rust_http_port() -> Iterator[int]:
    """Plain HTTP conformance server for the current SERVER (rust/python/go)."""
    yield from _http_variant_fixture("plain")


@pytest.fixture(scope="session")
def conformance_http_port(rust_http_port: int) -> int:
    """Alias of `rust_http_port` for the upstream `TestHealth`/`TestSticky`."""
    return rust_http_port


@pytest.fixture
def conformance_resource_soak_target() -> Iterator[Any]:
    """Expose one isolated Rust HTTP worker to the shared resource soak."""
    if ROLE != "server" or SERVER != "rust":
        pytest.skip("resource soak measures the Rust server role only")

    from vgi_rpc.conformance._resource_soak_pytest import (
        ResourceSoakLimits,
        ResourceSoakTarget,
    )

    proc, port = _spawn_http_variant("plain")
    try:
        def connect() -> contextlib.AbstractContextManager[Any]:
            return http_connect(ConformanceService, f"http://127.0.0.1:{port}")

        yield ResourceSoakTarget(
            name="rust-http",
            pid=proc.pid,
            connect=connect,
            limits=ResourceSoakLimits(
                rss_growth_bytes=32 * 1024 * 1024,
                rss_slope_bytes_per_epoch=2 * 1024 * 1024,
                descriptor_growth=3,
                thread_growth=2,
                child_growth=0,
            ),
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_http_no_compression_port() -> Iterator[int]:
    """HTTP conformance server booted with response compression disabled.

    Backs the shared ``test_empty_advertisement_means_never_compressed``
    case, which needs its own server because the state under test is a
    *server configuration* -- "I can produce no codecs" -- that no client
    request can induce. ``identity`` covers a client's ability to demand an
    uncompressed body; only a server booted this way emits the
    present-but-empty ``VGI-Supported-Encodings`` that distinguishes
    "speaks no compression" from the absent header of a legacy server.

    The fixture name is load-bearing: the shared suite looks it up with
    ``getfixturevalue`` and silently skips if it is missing.
    """
    yield from _http_variant_fixture("no_compression")


@pytest.fixture(scope="session")
def conformance_http_auth_reason_port() -> Iterator[int]:
    """HTTP worker that honours ``X-Conformance-Auth-Reason``.

    Backs the shared ``TestUnauthorized`` reason-code tests. Membership in
    the closed set is not enough on its own — a server answering every 401
    with ``unauthorized`` satisfies that. These tests prove the codes are
    *discriminated*, which is what makes them worth branching on.
    """
    yield from _http_variant_fixture("auth_reason")


@pytest.fixture(scope="session")
def conformance_http_cold_call_cache_port() -> Iterator[int]:
    """HTTP conformance server booted with the call-state cache disabled.

    Backs the shared ``TestColdCallStateCache`` group, which pins the rule
    that a client echoes the call token on every continuation. With the
    cache warm the server can resolve a call it already saw, so a client
    that never echoes still works — and only breaks once a continuation
    lands on a process with no cached entry. Disabling the cache makes
    every turn take that path.

    Only the Python reference server splits its stream state into call +
    cursor tokens today, so the variant is wired for ``SERVER == "python"``
    alone; the Rust and Go servers keep everything in the cursor and the
    group skips against them.

    The fixture name is load-bearing: the shared suite looks it up with
    ``getfixturevalue`` and silently skips if it is missing.
    """
    yield from _http_variant_fixture("cold_call_cache")


@pytest.fixture(scope="session")
def conformance_http_access_log(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[int, Path]]:
    """HTTP conformance server writing JSONL access records; yields ``(port, path)``.

    Backs the shared ``TestRequestId`` correlation case. Asserting that the
    ``X-Request-ID`` on a response equals the ``request_id`` in the record
    means reading back what the server logged for a request the suite made —
    nothing observable on the wire alone can stand in for it, which is why
    the case is gated on a fixture rather than derived.

    The fixture name is load-bearing: the shared suite looks it up with
    ``getfixturevalue`` and skips the correlation case if it is missing.

    Wired for ``SERVER == "rust"`` only. The Python reference grew
    ``--access-log`` on its serve script in 0.37.1, so an older checkout would
    spawn a worker that swallows the flag and writes nothing — a silent pass
    of an assertion that never ran, which is the failure mode this whole group
    exists to prevent.
    """
    if SERVER != "rust":
        pytest.skip(f"access-log worker not wired for SERVER={SERVER}")
    log_path = tmp_path_factory.mktemp("accesslog") / "conformance.jsonl"
    proc, port = _spawn_read_port([*_worker_cmd("http"), "--access-log", str(log_path)])
    try:
        yield port, log_path
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_fake_storage() -> Iterator[str]:
    """Run the in-memory ``vgi_rpc.conformance.fake_storage`` HTTP service."""
    from vgi_rpc.conformance.fake_storage import serve_in_thread

    base_url, shutdown = serve_in_thread()
    try:
        yield base_url
    finally:
        shutdown()


def _bytestream_external_cmd(storage_url: str) -> list[str]:
    """Argv for a byte-stream conformance server that externalises everything.

    ``_worker_cmd`` is handed the transport by name rather than left to infer
    it from which flags are present. That inference is the trap the shared docs
    call out: a ``_worker()`` that spells "byte stream" as *the absence of every
    flag* reroutes to an HTTP server the moment this fixture adds
    ``--fake-storage``, the fixture then speaks stdio to a server listening on a
    TCP port nobody dialled, and every test in the group times out in a read
    with no error text at all.

    One byte as the threshold, matching the reference: every data-bearing batch
    in the group must reach storage, or its upload assertions pass vacuously on
    batches that quietly stayed inline.
    """
    return [
        *_worker_cmd("stdio"),
        "--fake-storage",
        storage_url,
        "--externalize-threshold",
        "1",
    ]


@pytest.fixture(scope="session")
def conformance_bytestream_external_target(
    conformance_fake_storage: str,
) -> Iterator[Any]:
    """Supply an externalising byte-stream connection for ``TestExternalByteStream``.

    External-location pointers are not an HTTP feature — WIRE_PROTOCOL.md §12
    says so, and every transport that carries record batches carries pointer
    batches. This port has exactly one pointer resolver and its byte-stream
    client calls it, so the group *fails* rather than skips when this fixture is
    withheld: withholding is how that half stayed untested in the first place.

    Both ends are wired to the same fake storage, over a pipe:

    * ``role=server`` puts the reference Python client on the reading end of
      this port's writer, so it pins where per-emit metadata meets
      externalisation;
    * ``role=client`` puts this port's ``vgi-rpc-client`` on the reading end.
      With ``server=python`` the peer is the reference, which is the whole value
      of the leg — the reference externalises a stream *header*, and this port's
      server (like most) externalises only in the data path, so a port talking
      to itself never produces the pointer its own header reader must resolve.
    """
    from vgi_rpc.conformance._external_bytestream_pytest import ByteStreamExternalTarget
    from vgi_rpc.external import ExternalLocationConfig

    argv = _bytestream_external_cmd(conformance_fake_storage)
    # Fake storage vends `http://127.0.0.1` URLs that the default HTTPS-only
    # policy correctly refuses. Disabled here, in one fixture, rather than
    # loosened anywhere a production client could inherit it.
    external_config = ExternalLocationConfig(url_validator=None)

    def connect(
        on_log: Callable[[Message], None] | None = None,
    ) -> contextlib.AbstractContextManager[Any]:
        if ROLE == "client":
            from rust_client_proxy import RustClientProxy

            @contextlib.contextmanager
            def _driver_conn() -> Iterator[Any]:
                proxy = RustClientProxy(
                    "stdio", argv, on_log, external_config=external_config
                )
                try:
                    yield proxy
                finally:
                    proxy.close()

            return _driver_conn()

        @contextlib.contextmanager
        def _pipe_conn() -> Iterator[_RpcProxy]:
            transport = SubprocessTransport(argv)
            try:
                yield _RpcProxy(
                    ConformanceService,
                    transport,
                    on_log,
                    external_config=external_config,
                )
            finally:
                transport.close()

        return _pipe_conn()

    def uploaded_objects() -> int:
        response = httpx.get(f"{conformance_fake_storage}/_stats", timeout=5.0)
        response.raise_for_status()
        return int(response.json()["object_count"])

    try:
        yield ByteStreamExternalTarget(
            name=f"rust-{ROLE}-{SERVER}-pipe",
            connect=connect,
            uploaded_objects=uploaded_objects,
        )
    finally:
        # Releases whatever session the resolver kept for pointer fetches.
        external_config.fetch_config.close()


@pytest.fixture(scope="session")
def conformance_http_with_storage_port(conformance_fake_storage: str) -> Iterator[int]:
    """HTTP server wired to fake storage (no compression)."""
    yield from _http_variant_fixture("storage", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_with_zstd_storage_port(conformance_fake_storage: str) -> Iterator[int]:
    """HTTP server wired to fake storage with zstd compression."""
    yield from _http_variant_fixture("zstd_storage", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_external_security_port(conformance_fake_storage: str) -> Iterator[int]:
    """Rust worker with independent fetch caps and per-hop URL validation."""
    yield from _http_variant_fixture("external_security", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_externalize_always_port(conformance_fake_storage: str) -> Iterator[int]:
    """HTTP server forcing externalization of EVERY non-empty response batch."""
    yield from _http_variant_fixture("externalize_always", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_strict_cap_port() -> Iterator[int]:
    """HTTP server with strict body + externalised response caps."""
    yield from _http_variant_fixture("strict")


@pytest.fixture(scope="session")
def conformance_http_small_request_cap_port() -> Iterator[int]:
    """HTTP worker advertising a 4 KiB encoded and decoded request cap."""
    yield from _http_variant_fixture("small_request_cap")


@pytest.fixture(scope="session")
def conformance_http_externalized_cap_port(conformance_fake_storage: str) -> Iterator[int]:
    """Worker whose *external-channel* cap is the one that bites.

    Backs the shared ``TestExternalizedResponseCap`` group, which asserts
    that ``max_externalized_response_bytes`` is enforced rather than merely
    advertised in ``VGI-Max-Externalized-Response-Bytes``.

    Three settings make this fixture mean what it says:

    * storage is wired, so responses can travel the external channel at all;
    * ``--max-externalized-response-bytes`` is tight (64 KiB), so an
      externalised response overshoots it;
    * ``--max-response-bytes`` is deliberately *generous* (8 MiB). An
      externalised payload leaves only a pointer batch on the wire, so the
      body cap must never be what fails here — with both caps tight the
      group would pass while proving nothing about the external cap.

    ``--externalize-threshold`` is set to the reference's 4 KiB default (the
    Rust worker's storage mode otherwise defaults to 16 KiB) so the group's
    under-cap control still travels the external channel.
    """
    yield from _http_variant_fixture("externalized_cap", conformance_fake_storage)


@pytest.fixture(scope="session")
def proof_worker_factory() -> Iterator[Callable[..., Any]]:
    """Spawn Rust workers gated on proxy proof, for the shared TestProxyProof group.

    Only wired for SERVER == "rust"; other servers have their own harness and
    the shared group skips cleanly when this fixture is absent.
    """
    if SERVER != "rust":
        pytest.skip(f"proof worker not wired for SERVER={SERVER}")

    from vgi_rpc.conformance.proof_harness import ProofWorker, ProofWorkerConfig

    @contextlib.contextmanager
    def spawn(config: ProofWorkerConfig) -> Iterator[ProofWorker]:
        args = [
            RUST_WORKER,
            "--http-proof",
            "--proof-mode", config.mode,
            "--proof-origin-id", config.origin_id,
            "--proof-secrets", config.secrets,
            "--proof-skew", str(config.skew_seconds),
        ]
        if not config.replay_cache:
            args.append("--proof-no-replay-cache")
        proc, port = _spawn_read_port(args)
        try:
            # The Rust worker mounts proof mode under /vgi, mirroring auth mode.
            yield ProofWorker(port=port, prefix="/vgi", config=config)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    yield spawn


@pytest.fixture(scope="session")
def conformance_http_auth_port() -> Iterator[int]:
    """HTTP server with a reject-all auth callback."""
    proc, port = _spawn_http_variant("auth")
    try:
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Sticky failure-path fixtures (upstream TestSticky; see the reference repo's
# docs/sticky-sessions-spec.md §9.1)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def conformance_http_sticky_short_ttl_port() -> Iterator[int]:
    """A sticky worker whose default session TTL is short enough to outwait.

    Backs ``TestSticky::test_expired_session_surfaces_session_lost``; the main
    worker's 300s default is not something a test can sit out.
    """
    yield from _http_variant_fixture("sticky_short_ttl")


@pytest.fixture(scope="session")
def conformance_http_sticky_peer_ports() -> Iterator[tuple[int, int]]:
    """Two sticky workers sharing one AEAD key but reporting distinct server ids.

    Backs ``TestSticky::test_token_from_other_worker_rejected``.
    """
    proc_a, port_a = _spawn_http_variant("sticky_peer_a")
    proc_b, port_b = _spawn_http_variant("sticky_peer_b")
    try:
        yield port_a, port_b
    finally:
        for proc in (proc_a, proc_b):
            proc.terminate()
            proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_http_sticky_auth_port() -> Iterator[int]:
    """A sticky worker that authenticates the ``X-Conformance-Principal`` header.

    Backs ``TestSticky::test_cross_principal_replay_rejected``, which needs one
    worker reachable as two identities.
    """
    yield from _http_variant_fixture("sticky_auth")


@pytest.fixture(scope="session")
def conformance_http_cors_port(conformance_fake_storage: str) -> Iterator[int]:
    """HTTP worker that grants ``_CORS_ORIGIN`` cross-origin access.

    Backs the shared ``TestCors`` group, which is the one thing the rest of
    the suite structurally cannot check: every other test drives the server
    with a client that ignores CORS, so a capability header the server never
    exposes still passes everywhere else while being invisible to a browser.

    Needs its own worker because the plain one must stay CORS-off —
    ``TestCorsOffMode`` runs against that one and asserts it grants nothing.
    The fixture name is load-bearing: the shared suite looks it up with
    ``getfixturevalue`` and skips the whole group if it is missing.

    Storage mode is deliberate: the derived exposure check can only catch a
    missing entry for a header the worker actually advertises, so a *plain*
    worker here would silently skip the conditional half of the capability
    set -- the size caps and the upload-URL trio -- which are exactly the
    exposures a port is most likely to miss.
    """
    yield from _http_variant_fixture("cors", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_identity_port() -> Iterator[int]:
    """HTTP worker co-hosting ``vgi_rpc.Identity.v1`` with both hooks.

    Backs the shared identity group, whose every assertion reads deployment
    policy — who may introspect, what a credential resolves to, whether a
    grant is minted, how recently the caller authenticated. Against a worker
    whose allowlist and hooks are unknown no cross-port assertion exists, so
    the policy is pinned by ``IDENTITY_CONFORMANCE_FIXTURE.md`` and configured
    in the worker's ``identity_fixture`` module. The fixture name is
    load-bearing: the shared suite looks it up with ``getfixturevalue`` and
    skips the whole group, naming this fixture, if it is missing.

    Not the plain worker: the group asserts against *that* one that a
    deployment configuring no hook hosts no identity protocol at all.
    """
    yield from _http_variant_fixture("identity")


@pytest.fixture(scope="session")
def conformance_http_identity_introspect_only_port() -> Iterator[int]:
    """The same binary with the mint hook left out.

    Method-level narrowing — that an unconfigured hook makes its method absent
    rather than hosted-and-refusing, and shrinks the ``protocol_hash`` with it
    — is only observable against a *second* worker configured with one hook.
    """
    yield from _http_variant_fixture("identity_introspect_only")


def _short_unix_path(name: str) -> str:
    """Return a short /tmp path for a Unix domain socket (macOS 104-byte limit)."""
    fd, path = tempfile.mkstemp(prefix=f"vgi-rust-{name}-", suffix=".sock", dir="/tmp")
    os.close(fd)
    os.unlink(path)
    return path


def _wait_for_unix(path: str, timeout: float = 5.0) -> None:
    """Poll until a Unix domain socket is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(path)
                return
            finally:
                sock.close()
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            time.sleep(0.1)
    raise TimeoutError(f"Unix socket at {path} did not start within {timeout}s")


def _wait_for_tcp(host: str, port: int, timeout: float = 5.0) -> None:
    """Poll until a raw TCP or HTTP listener accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"TCP socket at {host}:{port} did not start within {timeout}s")


@pytest.fixture(scope="session")
def rust_unix_path() -> Iterator[str]:
    """Start Rust conformance Unix socket server."""
    path = _short_unix_path("conf")
    proc = subprocess.Popen(
        _worker_cmd("unix", path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().decode().strip()
        assert line == f"UNIX:{path}", f"Expected UNIX:{path}, got: {line!r}"
        _wait_for_unix(path)
        yield path
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def rust_tcp_addr() -> Iterator[tuple[str, int]]:
    """Start the selected conformance server on a raw TCP socket."""
    proc = subprocess.Popen(
        _worker_cmd("tcp", "127.0.0.1:0"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("TCP:"), f"Expected TCP:<host>:<port>, got: {line!r}"
        host, _, raw_port = line[len("TCP:") :].rpartition(":")
        port = int(raw_port)
        _wait_for_tcp(host, port)
        yield host, port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# The class name IS the wire protocol name: `_RpcProxy` / `http_connect` derive
# the routing key from it, and the worker registers this surface as
# `TransportKindProbe`. Before routing keys existed the name was free; now a
# mismatch is refused by the server, so this must stay in step with
# `conformance-worker/src/main.rs`.
class TransportKindProbe(Protocol):
    def report_transport_kind(self) -> str: ...


@pytest.fixture(scope="class")
def conformance_http_serve_start_fail_once_port() -> Iterator[int]:
    """Rust HTTP worker whose first startup hook panics, then retries."""
    if ROLE != "server" or SERVER != "rust":
        pytest.skip("serve-start lifecycle fixture validates the Rust server role")
    proc, port = _spawn_read_port(
        [RUST_WORKER, "--http", "--fail-serve-start-once"],
        tcp_only_ready=True,
    )
    try:
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="class")
def conformance_transport_kind_probes() -> tuple[tuple[str, Callable[[], str]], ...]:
    """Real Rust-worker probes for pipe, HTTP, Unix, and TCP kinds."""
    if ROLE != "server" or SERVER != "rust":
        pytest.skip("transport-kind probes validate the Rust server role")

    def probe_pipe() -> str:
        transport = SubprocessTransport([RUST_WORKER, "--transport-kind-probe"])
        try:
            return str(_RpcProxy(TransportKindProbe, transport, None).report_transport_kind())
        finally:
            transport.close()

    def probe_http() -> str:
        proc, port = _spawn_read_port([RUST_WORKER, "--http", "--transport-kind-probe"])
        try:
            with http_connect(TransportKindProbe, f"http://127.0.0.1:{port}") as proxy:
                return str(proxy.report_transport_kind())
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def probe_unix() -> str:
        path = _short_unix_path("kind")
        proc = subprocess.Popen(
            [RUST_WORKER, "--unix", path, "--transport-kind-probe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert proc.stdout is not None
            line = proc.stdout.readline().decode().strip()
            assert line == f"UNIX:{path}", f"Expected UNIX:{path}, got: {line!r}"
            _wait_for_unix(path)
            with unix_connect(TransportKindProbe, path) as proxy:
                return str(proxy.report_transport_kind())
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def probe_tcp() -> str:
        proc = subprocess.Popen(
            [RUST_WORKER, "--tcp", "127.0.0.1:0", "--transport-kind-probe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert proc.stdout is not None
            line = proc.stdout.readline().decode().strip()
            assert line.startswith("TCP:"), f"Expected TCP:<host>:<port>, got: {line!r}"
            host, _, raw_port = line[len("TCP:") :].rpartition(":")
            port = int(raw_port)
            _wait_for_tcp(host, port)
            with tcp_connect(TransportKindProbe, host, port) as proxy:
                return str(proxy.report_transport_kind())
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    return (
        ("pipe", probe_pipe),
        ("http", probe_http),
        ("unix", probe_unix),
        ("tcp", probe_tcp),
    )


ConnFactory = Callable[..., contextlib.AbstractContextManager[Any]]


_TRANSPORTS = os.environ.get(
    "VGI_TRANSPORTS", "pipe,subprocess,http,unix,tcp,http_externalize_always,shm_pipe"
).split(",")


class _ShmSubprocessTransport:
    """Adapter exposing ``.shm`` over a ``SubprocessTransport`` so the
    Python ``_RpcClient`` advertises the segment in request metadata.

    The Rust worker has no built-in ``ShmPipeTransport`` concept — it
    attaches dynamically when it sees ``vgi_rpc.shm_segment_name`` /
    ``vgi_rpc.shm_segment_size`` keys on the request batch, which is
    exactly what the Python client emits when ``transport.shm`` exists.
    """

    __slots__ = ("_inner", "_shm")

    def __init__(self, inner, shm) -> None:
        self._inner = inner
        self._shm = shm

    @property
    def reader(self):
        return self._inner.reader

    @property
    def writer(self):
        return self._inner.writer

    @property
    def shm(self):
        return self._shm

    def close(self) -> None:
        self._inner.close()


def _client_factory(
    param: str,
    on_log: Callable[[Message], None] | None,
    http_port: int | None,
    unix_path: str | None,
    tcp_addr: tuple[str, int] | None,
    ext_port: int | None,
) -> contextlib.AbstractContextManager[Any]:
    """Yield a Rust-client-backed proxy (VGI_CONFORMANCE_ROLE=client)."""
    from rust_client_proxy import RustClientProxy

    external_config = None
    if param == "shm_pipe":
        transport: str = "shm"
        target: Any = _worker_cmd("stdio")
    elif param in ("pipe", "subprocess"):
        transport = "stdio"
        target = _worker_cmd("stdio")
    elif param == "http":
        transport, target = "http", f"http://127.0.0.1:{http_port}"
    elif param == "http_externalize_always":
        from vgi_rpc.external import ExternalLocationConfig

        transport, target = "http", f"http://127.0.0.1:{ext_port}"
        external_config = ExternalLocationConfig(url_validator=None)
    elif param == "unix":
        transport, target = "unix", unix_path
    elif param == "tcp":
        transport, target = "tcp", f"{tcp_addr[0]}:{tcp_addr[1]}"
    else:
        raise AssertionError(f"unknown transport {param!r}")

    @contextlib.contextmanager
    def _conn() -> Iterator[Any]:
        proxy = RustClientProxy(transport, target, on_log, external_config=external_config)
        try:
            yield proxy
        finally:
            proxy.close()

    return _conn()


@pytest.fixture(params=_TRANSPORTS)
def conformance_conn(
    request: pytest.FixtureRequest,
    rust_transport: SubprocessTransport,
) -> ConnFactory:
    rust_http_port = request.getfixturevalue("rust_http_port") if request.param == "http" else None
    rust_unix_path = request.getfixturevalue("rust_unix_path") if request.param == "unix" else None
    rust_tcp_addr = request.getfixturevalue("rust_tcp_addr") if request.param == "tcp" else None
    ext_always_port = (
        request.getfixturevalue("conformance_http_externalize_always_port")
        if request.param == "http_externalize_always"
        else None
    )
    def factory(
        on_log: Callable[[Message], None] | None = None,
    ) -> contextlib.AbstractContextManager[Any]:
        if ROLE == "client":
            return _client_factory(
                request.param,
                on_log,
                rust_http_port,
                rust_unix_path,
                rust_tcp_addr,
                ext_always_port,
            )
        if request.param == "pipe":

            @contextlib.contextmanager
            def _pipe_conn() -> Iterator[_RpcProxy]:
                transport = SubprocessTransport([RUST_WORKER])
                try:
                    yield _RpcProxy(ConformanceService, transport, on_log)
                finally:
                    transport.close()

            return _pipe_conn()
        elif request.param == "http":
            return http_connect(
                ConformanceService,
                f"http://127.0.0.1:{rust_http_port}",
                on_log=on_log,
            )
        elif request.param == "http_externalize_always":
            from vgi_rpc.external import ExternalLocationConfig

            return http_connect(
                ConformanceService,
                f"http://127.0.0.1:{ext_always_port}",
                on_log=on_log,
                # The Rust worker's fake storage vends http:// download URLs;
                # disable the default HTTPS-only validator so the client
                # accepts them.
                external_location=ExternalLocationConfig(url_validator=None),
            )
        elif request.param == "unix":
            return unix_connect(
                ConformanceService,
                rust_unix_path,
                on_log=on_log,
            )
        elif request.param == "tcp":
            assert rust_tcp_addr is not None
            return tcp_connect(
                ConformanceService,
                rust_tcp_addr[0],
                rust_tcp_addr[1],
                on_log=on_log,
            )
        elif request.param == "shm_pipe":
            from vgi_rpc.shm import ShmSegment

            @contextlib.contextmanager
            def _shm_conn() -> Iterator[_RpcProxy]:
                shm = ShmSegment.create(4 * 1024 * 1024)
                inner = SubprocessTransport([RUST_WORKER])
                try:
                    transport = _ShmSubprocessTransport(inner, shm)
                    yield _RpcProxy(ConformanceService, transport, on_log)
                finally:
                    inner.close()
                    with contextlib.suppress(BufferError):
                        shm.close()
                    shm.unlink()

            return _shm_conn()
        else:
            # "subprocess" — shared transport
            @contextlib.contextmanager
            def _conn() -> Iterator[_RpcProxy]:
                yield _RpcProxy(ConformanceService, rust_transport, on_log)

            return _conn()

    return factory


_RAW_TRANSPORTS = [
    transport
    for transport in _TRANSPORTS
    if transport in {"pipe", "subprocess", "shm_pipe", "unix", "tcp"}
]


@pytest.fixture(params=_RAW_TRANSPORTS)
def conformance_raw_conn(
    request: pytest.FixtureRequest,
    rust_transport: SubprocessTransport,
) -> ConnFactory:
    """Raw byte-stream connections for adversarial framing tests.

    These are server-contract probes even in a client-role matrix, so they use
    the Python raw proxy rather than the typed Rust-client bridge.
    """
    unix_path = request.getfixturevalue("rust_unix_path") if request.param == "unix" else None
    tcp_addr = request.getfixturevalue("rust_tcp_addr") if request.param == "tcp" else None

    def factory(
        on_log: Callable[[Message], None] | None = None,
    ) -> contextlib.AbstractContextManager[Any]:
        if request.param == "pipe":

            @contextlib.contextmanager
            def _pipe_conn() -> Iterator[_RpcProxy]:
                transport = SubprocessTransport([RUST_WORKER])
                try:
                    yield _RpcProxy(ConformanceService, transport, on_log)
                finally:
                    transport.close()

            return _pipe_conn()
        if request.param == "subprocess":

            @contextlib.contextmanager
            def _shared_conn() -> Iterator[_RpcProxy]:
                yield _RpcProxy(ConformanceService, rust_transport, on_log)

            return _shared_conn()
        if request.param == "shm_pipe":
            from vgi_rpc.shm import ShmSegment

            @contextlib.contextmanager
            def _shm_conn() -> Iterator[_RpcProxy]:
                shm = ShmSegment.create(4 * 1024 * 1024)
                inner = SubprocessTransport([RUST_WORKER])
                try:
                    yield _RpcProxy(
                        ConformanceService,
                        _ShmSubprocessTransport(inner, shm),
                        on_log,
                    )
                finally:
                    inner.close()
                    with contextlib.suppress(BufferError):
                        shm.close()
                    shm.unlink()

            return _shm_conn()
        if request.param == "unix":
            assert unix_path is not None
            return unix_connect(ConformanceService, unix_path, on_log=on_log)
        if request.param == "tcp":
            assert tcp_addr is not None
            return tcp_connect(
                ConformanceService,
                tcp_addr[0],
                tcp_addr[1],
                on_log=on_log,
            )
        raise AssertionError(f"unknown raw transport {request.param!r}")

    return factory


# Import all tests from the conformance test module (PyPI package)
from vgi_rpc.conformance._pytest_suite import *  # noqa: F401,F403,E402


# Override: allow TestLargeData on all transports (the upstream suite skips
# non-pipe transports, but the Rust worker handles them fine).
class TestLargeData(TestLargeData):  # type: ignore[no-redef]  # noqa: F811
    @pytest.fixture(autouse=True)
    def _skip_non_pipe(self) -> None:
        pass


# -----------------------------------------------------------------------------
# Live describe conformance against the actual worker transport matrix.
# The upstream TestDescribeConformance runs in-process against a Python
# RpcServer — which covers the protocol format but not our implementation.
# -----------------------------------------------------------------------------

from vgi_rpc.conformance import run_describe_conformance  # noqa: E402
from vgi_rpc.introspect import introspect, DESCRIBE_VERSION  # noqa: E402
from vgi_rpc.http import http_introspect  # noqa: E402


@pytest.fixture(
    params=[t for t in _TRANSPORTS if t in ("pipe", "subprocess", "http", "unix", "tcp")]
)
def conformance_describe(request: pytest.FixtureRequest):  # type: ignore[no-untyped-def]
    """Return a ``ServiceDescription`` from a real introspection round trip
    against the Rust worker under test — the fixture the upstream
    ``TestDescribeConformance`` relies on. Parallels ``conformance_conn``'s
    transport matrix.

    Introspection is ``vgi_rpc.Reflection.v1`` (``list_protocols``, then
    ``describe``), which is what ``introspect`` / ``http_introspect`` speak.
    ``__describe__`` is retired: the worker refuses it with a message naming
    the replacement, so a harness still calling it would fail loudly rather
    than silently describe nothing.

    Both ``pipe`` and ``subprocess`` use a stdio subprocess (the Rust worker has
    no in-process server); a dedicated child is spawned so the shared transport
    is left undisturbed.
    """
    param = request.param
    if ROLE == "client":
        from rust_client_proxy import RustClientProxy

        if param in ("pipe", "subprocess"):
            tr, tgt = "stdio", _worker_cmd("stdio")
        elif param == "http":
            tr, tgt = "http", f"http://127.0.0.1:{request.getfixturevalue('rust_http_port')}"
        elif param == "unix":
            tr, tgt = "unix", request.getfixturevalue("rust_unix_path")
        elif param == "tcp":
            host, port = request.getfixturevalue("rust_tcp_addr")
            tr, tgt = "tcp", f"{host}:{port}"
        else:
            raise AssertionError(f"unknown describe transport: {param!r}")
        proxy = RustClientProxy(tr, tgt)
        try:
            return proxy.describe()
        finally:
            proxy.close()
    if param in ("pipe", "subprocess"):
        transport = SubprocessTransport([RUST_WORKER])
        try:
            return introspect(transport)
        finally:
            transport.close()
    if param == "http":
        port = request.getfixturevalue("rust_http_port")
        return http_introspect(f"http://127.0.0.1:{port}")
    if param == "unix":
        path = request.getfixturevalue("rust_unix_path")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(path)
        except BaseException:
            sock.close()
            raise
        transport = UnixTransport(sock)
        try:
            return introspect(transport)
        finally:
            transport.close()
    if param == "tcp":
        host, port = request.getfixturevalue("rust_tcp_addr")
        sock = socket.create_connection((host, port))
        transport = TcpTransport(sock)
        try:
            return introspect(transport)
        finally:
            transport.close()
    raise AssertionError(f"unknown describe transport: {param!r}")


class TestMandatoryHttpCodecs:
    """Compression-enabled conformance workers must provide both codecs."""

    def test_server_advertises_zstd_and_gzip(self, rust_http_port: int) -> None:
        response = httpx.options(f"http://127.0.0.1:{rust_http_port}/health")
        response.raise_for_status()
        advertised = {
            item.strip().lower()
            for item in response.headers.get("vgi-supported-encodings", "").split(",")
            if item.strip()
        }
        assert advertised == {"zstd", "gzip"}


@pytest.mark.skipif(
    SERVER != "rust",
    reason="Rust-worker describe smoke test (uses the Python introspect client directly)",
)
class TestRustDescribeConformance:
    """Run the describe conformance suite against the real Rust worker."""

    def test_describe_via_pipe(self, rust_transport: SubprocessTransport) -> None:
        # Use a dedicated subprocess so we don't disturb the shared transport.
        transport = SubprocessTransport([RUST_WORKER])
        try:
            desc = introspect(transport)
        finally:
            transport.close()
        _assert_describe(desc)

    def test_describe_via_http(self, rust_http_port: int) -> None:
        desc = http_introspect(f"http://127.0.0.1:{rust_http_port}")
        _assert_describe(desc)


def _assert_describe(desc) -> None:  # type: ignore[no-untyped-def]
    assert desc.protocol_name == "ConformanceService"
    assert desc.describe_version == DESCRIBE_VERSION
    assert len(desc.methods) == 89, sorted(desc.methods.keys())
    suite = run_describe_conformance(desc)
    if not suite.success:
        failures = [r for r in suite.results if not r.passed]
        details = "\n".join(f"  {r.name}: {r.error}" for r in failures)
        raise AssertionError(
            f"{suite.failed}/{suite.total} describe conformance tests failed:\n{details}"
        )
