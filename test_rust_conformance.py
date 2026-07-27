"""Run Python conformance tests against the Rust conformance worker."""
import contextlib
import os
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from vgi_rpc.conformance import ConformanceService
from vgi_rpc.http import http_connect
from vgi_rpc.log import Message
from vgi_rpc.rpc import SubprocessTransport, UnixTransport, _RpcProxy, unix_connect

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

    mode ∈ {"stdio", "http", "unix"}. The Rust and Go workers default
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
    else:  # rust / go share the same flag surface
        if mode == "stdio":
            return base
        if mode == "http":
            return base + ["--http"]
        if mode == "unix":
            return base + ["--unix", path]
    raise AssertionError(f"unknown worker mode {mode!r}")


# --- Python reference HTTP servers (full-featured: sticky, storage, strict,
# auth) used when SERVER=python so the Rust client's external/sticky/413/strict
# paths validate against the canonical Python implementation. -----------------
_VENV_PY = os.environ.get("VGI_PYTHON_BIN", "/Users/rusty/Development/vgi-rpc/.venv/bin/python")
# Directory holding the Python reference serve_conformance_*.py scripts. These
# live in the vgi-rpc *repo* (not the PyPI wheel), so cross-language client runs
# against the Python server set VGI_PY_TESTS_DIR to a checkout of that repo.
_PY_TESTS = Path(
    os.environ.get("VGI_PY_TESTS_DIR", str(Path.home() / "Development" / "vgi-rpc" / "tests"))
)
_PY_SERVE_HTTP = str(_PY_TESTS / "serve_conformance_http.py")
_PY_SERVE_STRICT = str(_PY_TESTS / "serve_conformance_http_strict.py")
_PY_SERVE_AUTH = str(_PY_TESTS / "serve_conformance_http_auth.py")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn_read_port(args: list[str], *, expect_port: int | None = None) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    line = proc.stdout.readline().decode().strip()
    assert line.startswith("PORT:"), f"Expected PORT:<n>, got: {line!r} (args={args})"
    port = int(line.split(":", 1)[1])
    if expect_port is not None:
        assert port == expect_port, f"expected PORT:{expect_port}, got {port}"
    _wait_for_http(port)
    return proc, port


def _start_rust_http_with_storage(
    storage_url: str | None,
    zstd: bool,
    *,
    externalize_threshold: int | None = None,
    max_request_bytes: int | None = None,
) -> tuple[subprocess.Popen, int]:
    args = [RUST_WORKER, "--http-with-storage", storage_url or ""]
    if zstd:
        args.append("--zstd")
    if externalize_threshold is not None:
        args += ["--externalize-threshold", str(externalize_threshold)]
    if max_request_bytes is not None:
        args += ["--max-request-bytes", str(max_request_bytes)]
    return _spawn_read_port(args)


def _spawn_http_variant(variant: str, storage_url: str | None = None) -> tuple[subprocess.Popen, int]:
    """Spawn an HTTP conformance server of `variant` for the current SERVER.

    variant ∈ {plain, no_compression, storage, zstd_storage, externalize_always,
    strict, auth}.
    Raises ``pytest.skip`` for (server, variant) combinations not wired here
    (the Go conformance binary doesn't expose the storage/strict/auth modes).
    """
    if SERVER == "python":
        if variant == "plain":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http"])
        if variant == "no_compression":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_HTTP, "--http", "--no-compression"])
        if variant in ("storage", "zstd_storage", "externalize_always"):
            port = _free_port()
            args = [_VENV_PY, _PY_SERVE_HTTP, "--port", str(port), "--fake-storage", storage_url or ""]
            if variant == "zstd_storage":
                args += ["--compression", "zstd"]
            if variant == "externalize_always":
                args += ["--externalize-threshold", "1", "--max-request-bytes", "1048576"]
            return _spawn_read_port(args, expect_port=port)
        if variant == "strict":
            return _spawn_read_port([_VENV_PY, _PY_SERVE_STRICT])
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
        if variant == "externalize_always":
            return _start_rust_http_with_storage(
                storage_url, zstd=False, externalize_threshold=1, max_request_bytes=1024 * 1024
            )
        if variant == "strict":
            return _spawn_read_port([RUST_WORKER, "--http", "--strict"])
        if variant == "auth":
            return _spawn_read_port([RUST_WORKER, "--http-auth"])
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
def conformance_fake_storage() -> Iterator[str]:
    """Run the in-memory ``vgi_rpc.conformance.fake_storage`` HTTP service."""
    from vgi_rpc.conformance.fake_storage import serve_in_thread

    base_url, shutdown = serve_in_thread()
    try:
        yield base_url
    finally:
        shutdown()


@pytest.fixture(scope="session")
def conformance_http_with_storage_port(conformance_fake_storage: str) -> Iterator[int]:
    """HTTP server wired to fake storage (no compression)."""
    yield from _http_variant_fixture("storage", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_with_zstd_storage_port(conformance_fake_storage: str) -> Iterator[int]:
    """HTTP server wired to fake storage with zstd compression."""
    yield from _http_variant_fixture("zstd_storage", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_externalize_always_port(conformance_fake_storage: str) -> Iterator[int]:
    """HTTP server forcing externalization of EVERY non-empty response batch."""
    yield from _http_variant_fixture("externalize_always", conformance_fake_storage)


@pytest.fixture(scope="session")
def conformance_http_strict_cap_port() -> Iterator[int]:
    """HTTP server with strict body + externalised response caps."""
    yield from _http_variant_fixture("strict")


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


ConnFactory = Callable[..., contextlib.AbstractContextManager[Any]]


_TRANSPORTS = os.environ.get(
    "VGI_TRANSPORTS", "pipe,subprocess,http,unix,http_externalize_always,shm_pipe"
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
    ext_always_port = (
        request.getfixturevalue("conformance_http_externalize_always_port")
        if request.param == "http_externalize_always"
        else None
    )
    def factory(
        on_log: Callable[[Message], None] | None = None,
    ) -> contextlib.AbstractContextManager[Any]:
        if ROLE == "client":
            return _client_factory(request.param, on_log, rust_http_port, rust_unix_path, ext_always_port)
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


# Import all tests from the conformance test module (PyPI package)
from vgi_rpc.conformance._pytest_suite import *  # noqa: F401,F403,E402


from vgi_rpc.rpc import AnnotatedBatch, RpcError  # noqa: E402


# The Go conformance server's __describe__ advertises 76 methods (its port
# implements a subset / names some differently), not the canonical 81 — a
# Go-*server* describe discrepancy that the Rust client relays faithfully (all
# method calls still round-trip). Skip the describe-metadata conformance checks
# for the Go server; they're validated against the rust + python servers.
class TestDescribeConformance(TestDescribeConformance):  # type: ignore[no-redef]  # noqa: F811
    pytestmark = pytest.mark.skipif(
        SERVER == "go",
        reason="Go server __describe__ reports 76 methods, not the canonical 81",
    )


# Override: allow TestLargeData on all transports (the upstream suite skips
# non-pipe transports, but the Rust worker handles them fine).
class TestLargeData(TestLargeData):  # type: ignore[no-redef]  # noqa: F811
    @pytest.fixture(autouse=True)
    def _skip_non_pipe(self) -> None:
        pass


# Override: the Rust server drains client input after stream init errors, so
# these tests work on all transports (the upstream suite skips them).
class TestProducerStream(TestProducerStream):  # type: ignore[no-redef]  # noqa: F811
    def test_produce_error_on_init(self, conformance_conn: ConnFactory) -> None:
        with conformance_conn() as proxy, pytest.raises(RpcError, match="intentional init error"):
            list(proxy.produce_error_on_init())


class TestExchangeStream(TestExchangeStream):  # type: ignore[no-redef]  # noqa: F811
    def test_error_on_init(self, conformance_conn: ConnFactory) -> None:
        with conformance_conn() as proxy:
            with pytest.raises(RpcError, match="intentional exchange init error"):
                session = proxy.exchange_error_on_init()
                # HTTP raises during init; pipe/subprocess raises on first exchange.
                session.exchange(AnnotatedBatch.from_pydict({"value": [1.0]}))


# -----------------------------------------------------------------------------
# Live describe conformance against the actual Rust worker (pipe + http).
# The upstream TestDescribeConformance runs in-process against a Python
# RpcServer — which covers the protocol format but not our implementation.
# -----------------------------------------------------------------------------

from vgi_rpc.conformance import run_describe_conformance  # noqa: E402
from vgi_rpc.introspect import introspect, DESCRIBE_METHOD_NAME, DESCRIBE_VERSION  # noqa: E402
from vgi_rpc.http import http_introspect  # noqa: E402


@pytest.fixture(params=[t for t in _TRANSPORTS if t in ("pipe", "subprocess", "http", "unix")])
def conformance_describe(request: pytest.FixtureRequest):  # type: ignore[no-untyped-def]
    """Return a ``ServiceDescription`` from a real ``__describe__`` call to the
    Rust worker under test — the fixture the upstream ``TestDescribeConformance``
    relies on. Parallels ``conformance_conn``'s transport matrix.

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
    raise AssertionError(f"unknown describe transport: {param!r}")


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
    assert len(desc.methods) == 81, sorted(desc.methods.keys())
    suite = run_describe_conformance(desc)
    if not suite.success:
        failures = [r for r in suite.results if not r.passed]
        details = "\n".join(f"  {r.name}: {r.error}" for r in failures)
        raise AssertionError(
            f"{suite.failed}/{suite.total} describe conformance tests failed:\n{details}"
        )
