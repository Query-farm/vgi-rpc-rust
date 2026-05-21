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
from vgi_rpc.rpc import SubprocessTransport, _RpcProxy, unix_connect

RUST_WORKER = os.environ.get(
    "RUST_CONFORMANCE_WORKER",
    str(Path(__file__).parent / "conformance-worker-rust"),
)


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


@pytest.fixture(scope="session")
def rust_http_port() -> Iterator[int]:
    """Start Rust conformance HTTP server."""
    proc = subprocess.Popen(
        [RUST_WORKER, "--http"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("PORT:"), f"Expected PORT:<n>, got: {line!r}"
        port = int(line.split(":", 1)[1])

        _wait_for_http(port)

        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_http_port(rust_http_port: int) -> int:
    """Alias of `rust_http_port` for the upstream `TestHealth` fixture."""
    return rust_http_port


@pytest.fixture(scope="session")
def conformance_fake_storage() -> Iterator[str]:
    """Run the in-memory ``vgi_rpc.conformance.fake_storage`` HTTP service."""
    from vgi_rpc.conformance.fake_storage import serve_in_thread

    base_url, shutdown = serve_in_thread()
    try:
        yield base_url
    finally:
        shutdown()


def _start_rust_http_with_storage(
    storage_url: str,
    zstd: bool,
    *,
    externalize_threshold: int | None = None,
    max_request_bytes: int | None = None,
) -> tuple[subprocess.Popen, int]:
    args = [RUST_WORKER, "--http-with-storage", storage_url]
    if zstd:
        args.append("--zstd")
    if externalize_threshold is not None:
        args += ["--externalize-threshold", str(externalize_threshold)]
    if max_request_bytes is not None:
        args += ["--max-request-bytes", str(max_request_bytes)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    line = proc.stdout.readline().decode().strip()
    assert line.startswith("PORT:"), f"Expected PORT:<n>, got: {line!r}"
    port = int(line.split(":", 1)[1])
    _wait_for_http(port)
    return proc, port


@pytest.fixture(scope="session")
def conformance_http_with_storage_port(conformance_fake_storage: str) -> Iterator[int]:
    """Run the Rust worker wired to fake storage (no compression)."""
    proc, port = _start_rust_http_with_storage(conformance_fake_storage, zstd=False)
    try:
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_http_with_zstd_storage_port(conformance_fake_storage: str) -> Iterator[int]:
    """Run the Rust worker wired to fake storage with zstd compression."""
    proc, port = _start_rust_http_with_storage(conformance_fake_storage, zstd=True)
    try:
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_http_externalize_always_port(conformance_fake_storage: str) -> Iterator[int]:
    """Run the Rust worker forcing externalization of EVERY non-empty response batch.

    Threshold=1 byte makes every data-bearing batch externalize via the
    upload-URL pointer flow; the inline-request cap stays at 1 MiB so
    normal-sized client requests still flow inline. Used as a transport
    variant in ``conformance_conn`` to double-check that externalization
    is observationally indistinguishable from inline transmission across
    the entire conformance method matrix.
    """
    proc, port = _start_rust_http_with_storage(
        conformance_fake_storage,
        zstd=False,
        externalize_threshold=1,
        max_request_bytes=1024 * 1024,
    )
    try:
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_http_strict_cap_port() -> Iterator[int]:
    """Run the Rust worker with strict body + externalised response caps.

    Used by `TestHttpResponseCap` / `TestHttpResponseCapSoftWire` to
    deliberately overshoot the cap on unary / exchange / producer paths.
    Defaults mirror the Python `serve_conformance_http_strict.py`
    fixture: 1 MiB inline + 1 MiB externalised.
    """
    proc = subprocess.Popen(
        [RUST_WORKER, "--http", "--strict"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("PORT:"), f"Expected PORT:<n>, got: {line!r}"
        port = int(line.split(":", 1)[1])
        _wait_for_http(port)
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def conformance_http_auth_port() -> Iterator[int]:
    """Run the Rust worker with a reject-all auth callback under `/vgi/`."""
    proc = subprocess.Popen(
        [RUST_WORKER, "--http-auth"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("PORT:"), f"Expected PORT:<n>, got: {line!r}"
        port = int(line.split(":", 1)[1])
        _wait_for_http(port)
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
        [RUST_WORKER, "--unix", path],
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
