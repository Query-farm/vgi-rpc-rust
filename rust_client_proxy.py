"""Python shim that drives the Rust ``vgi-rpc-client`` for conformance.

The shim reconstructs the proxy / stream-session / session-view surface the
imported conformance test bodies expect, but forwards every call to the Rust
``vgi-rpc-conformance-client-driver`` subprocess over a tiny JSONL control
protocol. Crucially it **reuses the canonical Python value encoders/decoders**
(`_send_request`, `_read_unary_response`, `_read_stream_header`,
`AnnotatedBatch`) so no value marshaling lives here — the bytes crossing the
control boundary are Arrow IPC streams + a method name, and the Rust client
does all real wire framing / transport / streaming / envelope parsing.
"""
from __future__ import annotations

import base64
import io
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pyarrow as pa
from pyarrow import ipc

from vgi_rpc.conformance import ConformanceService
from vgi_rpc.log import Level, Message
from vgi_rpc.rpc import AnnotatedBatch, RpcError
from vgi_rpc.rpc._types import rpc_methods
from vgi_rpc.rpc._wire import _read_stream_header, _read_unary_response, _send_request
from vgi_rpc.rpc._types import MethodType
from vgi_rpc.utils import IpcValidation, ValidatedReader

_DRIVER = os.environ.get(
    "VGI_CLIENT_DRIVER",
    str(Path(__file__).parent / "target" / "debug" / "vgi-rpc-conformance-client-driver"),
)


def _b64e(b: bytes) -> str:
    return base64.standard_b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.standard_b64decode(s.encode("ascii"))


def _serialize_batch(batch: pa.RecordBatch, custom_metadata: Any) -> bytes:
    """Serialize one batch (+ optional custom metadata) as an IPC stream."""
    buf = io.BytesIO()
    with ipc.new_stream(buf, batch.schema) as w:
        if custom_metadata:
            w.write_batch(batch, custom_metadata=custom_metadata)
        else:
            w.write_batch(batch)
    return buf.getvalue()


def _reader(b: bytes) -> ValidatedReader:
    return ValidatedReader(ipc.open_stream(io.BytesIO(b)), IpcValidation.FULL)


class RustClientProxy:
    """Drives a Rust client subprocess; mimics the ``_RpcProxy`` surface."""

    def __init__(
        self,
        transport: str,
        target: Any,
        on_log: Callable[[Message], None] | None = None,
        *,
        external_config: Any = None,
        compression_level: Any = 3,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._methods = rpc_methods(ConformanceService)
        self._on_log = on_log
        # external_config is a flag here: when set, the *Rust* client resolves
        # external-location pointers (we must NOT resolve Python-side, or we'd
        # mask the Rust client). compression_level threads to the Rust client.
        self._external = external_config is not None
        self._compression_level = compression_level
        self._protocol_version = vars(ConformanceService).get("protocol_version")
        self._headers = headers or {}
        self._proc = subprocess.Popen(
            [_DRIVER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=0,
        )
        self._connect(transport, target)

    # --- control channel --------------------------------------------------
    def _send(self, obj: dict) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        self._proc.stdin.flush()

    def _recv(self) -> dict:
        assert self._proc.stdout is not None
        line = self._proc.stdout.readline()
        if not line:
            raise RpcError("TransportError", "client driver closed the control channel", "")
        return json.loads(line.decode("utf-8"))

    def _connect(self, transport: str, target: Any) -> None:
        self._send(
            {
                "op": "connect",
                "transport": transport,
                "target": target,
                "external": self._external,
                "compression_level": self._compression_level,
                # Default request headers, e.g. the identity the upstream
                # sticky cross-principal test pins on its client.
                "headers": self._headers,
            }
        )
        resp = self._recv()
        if not resp.get("ok"):
            raise RpcError("TransportError", f"driver connect failed: {resp.get('error')}", "")

    def _replay_logs(self, logs: list[dict] | None) -> None:
        if not logs or self._on_log is None:
            return
        for entry in logs:
            level = Level[entry["level"]]
            extra = entry.get("extra") or {}
            self._on_log(Message(level, entry["message"], **extra))

    @staticmethod
    def _raise_if_error(resp: dict) -> None:
        err = resp.get("error")
        if err:
            raise RpcError(err["error_type"], err["error_message"], err.get("traceback", "") or "")

    # --- proxy surface ----------------------------------------------------
    def __getattr__(self, name: str) -> Any:
        info = self._methods.get(name)
        if info is None:
            raise AttributeError(f"{ConformanceService.__name__} has no RPC method '{name}'")
        if info.method_type == MethodType.UNARY:
            caller = self._make_unary(info)
        else:
            caller = self._make_stream(info)
        self.__dict__[name] = caller
        return caller

    def _request_bytes(self, info: Any, kwargs: dict) -> bytes:
        buf = io.BytesIO()
        _send_request(buf, info, kwargs, protocol_version=self._protocol_version)
        return buf.getvalue()

    def _make_unary(self, info: Any) -> Callable[..., object]:
        def caller(**kwargs: object) -> object:
            req = self._request_bytes(info, kwargs)
            self._send({"op": "unary", "request_b64": _b64e(req)})
            resp = self._recv()
            if not resp.get("ok"):
                raise RpcError("TransportError", str(resp.get("error")), "")
            self._replay_logs(resp.get("logs"))
            self._raise_if_error(resp)
            result_b64 = resp.get("result_b64")
            if result_b64 is None:
                return None
            reader = _reader(_b64d(result_b64))
            # ext=None: the Rust client already resolved any external pointer.
            return _read_unary_response(reader, info, None, None)

        return caller

    def _make_stream(self, info: Any) -> Callable[..., "RustStreamSession"]:
        def caller(**kwargs: object) -> "RustStreamSession":
            req = self._request_bytes(info, kwargs)
            self._send(
                {
                    "op": "stream_open",
                    "request_b64": _b64e(req),
                    "is_exchange": bool(info.is_exchange),
                    "has_header": info.header_type is not None,
                }
            )
            resp = self._recv()
            if not resp.get("ok"):
                raise RpcError("TransportError", str(resp.get("error")), "")
            self._replay_logs(resp.get("logs"))
            self._raise_if_error(resp)
            header = None
            header_b64 = resp.get("header_b64")
            if header_b64 and info.header_type is not None:
                header = _read_stream_header(
                    io.BytesIO(_b64d(header_b64)),
                    info.header_type,
                    IpcValidation.FULL,
                    self._on_log,
                    None,
                )
            return RustStreamSession(self, info, header)

        return caller

    def describe(self) -> Any:
        from vgi_rpc.introspect import parse_describe_batch

        self._send({"op": "describe"})
        resp = self._recv()
        if not resp.get("ok"):
            raise RpcError("TransportError", str(resp.get("error")), "")
        reader = _reader(_b64d(resp["result_b64"]))
        batch, cm = reader.read_next_batch_with_custom_metadata()
        return parse_describe_batch(batch, cm)

    def with_session_token(self, token: Any = None) -> Any:
        """Sticky-session scope: subsequent calls on the returned view carry
        VGI-Session headers; on exit the session is torn down (best-effort
        DELETE unless detached)."""
        import contextlib

        proxy = self

        @contextlib.contextmanager
        def _scope() -> Any:
            proxy._send({"op": "session_begin", "token": token})
            proxy._recv()
            view = RustSessionView(proxy)
            try:
                yield view
            finally:
                proxy._send({"op": "session_end"})
                proxy._recv()

        return _scope()

    def _admin(self, op: str, **extra: Any) -> dict:
        self._send({"op": op, **extra})
        resp = self._recv()
        if not resp.get("ok"):
            raise RpcError("TransportError", str(resp.get("error")), "")
        return resp

    def close(self) -> None:
        try:
            self._send({"op": "shutdown"})
        except Exception:
            pass
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()


class RustStreamSession:
    """Mimics ``StreamSession`` over the driver control channel."""

    def __init__(self, proxy: RustClientProxy, info: Any, header: Any) -> None:
        self._proxy = proxy
        self._info = info
        self._header = header
        # The Rust driver's stream sub-loop exits the moment the stream
        # terminates (EOS, error, cancel, or close). `_active` tracks whether
        # the sub-loop is still listening; once False the shim must never send
        # another stream op (it would otherwise hit the driver's main loop).
        self._active = True
        self._cancelled = False
        self._finished = False
        self._closed = False

    @property
    def header(self) -> Any:
        return self._header

    def typed_header(self, header_type: type) -> Any:
        if not isinstance(self._header, header_type):
            raise TypeError(f"header is {type(self._header).__name__}, expected {header_type.__name__}")
        return self._header

    def _decode_batch(self, resp: dict) -> AnnotatedBatch:
        # The Rust client has already resolved any external-location pointer,
        # so we never resolve Python-side (that would mask the Rust client).
        reader = _reader(_b64d(resp["batch_b64"]))
        batch, cm = reader.read_next_batch_with_custom_metadata()
        return AnnotatedBatch(batch=batch, custom_metadata=cm)

    def tick(self, custom_metadata: Any = None) -> AnnotatedBatch:
        if self._cancelled:
            raise RpcError("ProtocolError", "stream cancelled", "")
        if self._finished or not self._active:
            raise StopIteration
        request: dict[str, Any] = {"op": "tick"}
        if custom_metadata is not None:
            empty = pa.RecordBatch.from_arrays([], schema=pa.schema([]))
            request["input_b64"] = _b64e(_serialize_batch(empty, custom_metadata))
        self._proxy._send(request)
        resp = self._proxy._recv()
        if not resp.get("ok"):
            self._active = False
            raise RpcError("TransportError", str(resp.get("error")), "")
        self._proxy._replay_logs(resp.get("logs"))
        if resp.get("error"):
            self._active = False
            self._finished = True
            self._proxy._raise_if_error(resp)
        if resp.get("done"):
            self._active = False
            self._finished = True
            raise StopIteration
        return self._decode_batch(resp)

    def __iter__(self) -> "RustStreamSession":
        return self

    def __next__(self) -> AnnotatedBatch:
        return self.tick()

    def next_with_token(self) -> tuple[AnnotatedBatch, str | None]:
        """Return the next native-client batch and its opaque resume token."""
        if self._cancelled:
            raise RpcError("ProtocolError", "stream cancelled", "")
        if self._finished or not self._active:
            raise StopIteration
        self._proxy._send({"op": "next_with_token"})
        resp = self._proxy._recv()
        if not resp.get("ok"):
            self._active = False
            raise RpcError("TransportError", str(resp.get("error")), "")
        self._proxy._replay_logs(resp.get("logs"))
        if resp.get("error"):
            self._active = False
            self._finished = True
            self._proxy._raise_if_error(resp)
        if resp.get("done") or resp.get("batch_b64") is None:
            self._active = False
            self._finished = True
            raise StopIteration
        return self._decode_batch(resp), resp.get("token")

    def exchange(self, input: AnnotatedBatch) -> AnnotatedBatch:
        if self._cancelled or self._closed:
            raise RpcError("ProtocolError", "stream closed", "")
        if self._finished or not self._active:
            raise RpcError("ProtocolError", "stream finished", "")
        payload = _serialize_batch(input.batch, input.custom_metadata)
        self._proxy._send({"op": "exchange", "input_b64": _b64e(payload)})
        resp = self._proxy._recv()
        if not resp.get("ok"):
            self._active = False
            raise RpcError("TransportError", str(resp.get("error")), "")
        self._proxy._replay_logs(resp.get("logs"))
        if resp.get("error"):
            self._active = False
            self._finished = True
            self._proxy._raise_if_error(resp)
        if resp.get("done") or resp.get("batch_b64") is None:
            self._active = False
            self._finished = True
            raise RpcError("ProtocolError", "exchange returned no batch", "")
        return self._decode_batch(resp)

    def cancel(self) -> None:
        if self._cancelled or not self._active:
            self._cancelled = True
            return
        self._proxy._send({"op": "cancel"})
        resp = self._proxy._recv()
        self._proxy._replay_logs(resp.get("logs"))
        self._cancelled = True
        self._active = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._active:
            self._proxy._send({"op": "close"})
            self._proxy._recv()
            self._active = False

    def __enter__(self) -> "RustStreamSession":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class RustSessionView:
    """Mimics the HTTP ``_SessionView``: RPC calls delegate to the proxy (the
    Rust client has the sticky session active, so requests carry the session
    headers), plus session-token / echo-header / detach accessors."""

    def __init__(self, proxy: RustClientProxy) -> None:
        object.__setattr__(self, "_proxy", proxy)

    def __getattr__(self, name: str) -> Any:
        # Delegate RPC method names (open_counter, stream_session_counter, ...)
        # to the underlying proxy, which routes them through the active session.
        return getattr(object.__getattribute__(self, "_proxy"), name)

    def current_session_token(self) -> Any:
        return self._proxy._admin("session_token").get("token")

    def current_echo_headers(self) -> dict:
        return self._proxy._admin("session_echo_headers").get("headers") or {}

    def detach(self) -> Any:
        return self._proxy._admin("session_detach").get("token")


# ---------------------------------------------------------------------------
# Module-level HTTP helpers (monkeypatched over vgi_rpc.http under client role)
# ---------------------------------------------------------------------------


class _Caps:
    def __init__(self, d: dict) -> None:
        self.sticky_enabled = bool(d.get("sticky_enabled"))
        self.sticky_default_ttl = d.get("sticky_default_ttl")
        self.sticky_echo_headers = list(d.get("sticky_echo_headers") or [])
        self.upload_url_support = bool(d.get("upload_url_support"))
        self.max_request_bytes = d.get("max_request_bytes")
        self.max_response_bytes = d.get("max_response_bytes")
        self.max_externalized_response_bytes = d.get("max_externalized_response_bytes")
        self.externalization_enabled = bool(d.get("externalization_enabled"))
        self.max_upload_bytes = d.get("max_upload_bytes")
        self.supported_encodings = list(d.get("supported_encodings") or [])


class _UploadUrl:
    def __init__(self, d: dict) -> None:
        self.upload_url = d["upload_url"]
        self.download_url = d["download_url"]
        self.expires_at = d.get("expires_at")


def _target_and_headers(base_url: Any, client: Any) -> tuple[Any, dict[str, str]]:
    """Resolve ``http_connect``'s ``base_url`` / ``client`` pair for the Rust driver.

    ``http_connect`` accepts either a URL or a pre-built ``httpx.Client``; the
    upstream sticky cross-principal test uses the latter to pin an identity
    header. The Rust client takes a URL plus default headers, so unwrap the
    client into that shape. Only headers the caller actually added are
    forwarded — httpx installs its own defaults (accept, accept-encoding,
    user-agent, connection) which the Rust client sets for itself.
    """
    if client is None:
        return base_url, {}
    try:
        import httpx
    except ModuleNotFoundError:
        import httpx2 as httpx

    with httpx.Client() as stock_client:
        stock = {k.lower() for k in stock_client.headers}
    headers = {k: v for k, v in client.headers.items() if k.lower() not in stock}
    return str(client.base_url), headers


def rust_http_connect(
    protocol: Any,
    base_url: Any = None,
    *,
    on_log: Callable[[Message], None] | None = None,
    external_location: Any = None,
    compression_level: Any = 3,
    prefix: Any = None,
    client: Any = None,
    **_kw: Any,
) -> Any:
    """Drop-in for ``vgi_rpc.http.http_connect`` that routes through the Rust
    client (used under VGI_CONFORMANCE_ROLE=client)."""
    import contextlib

    target, headers = _target_and_headers(base_url, client)

    @contextlib.contextmanager
    def _cm() -> Any:
        proxy = RustClientProxy(
            "http",
            target,
            on_log,
            external_config=external_location,
            compression_level=compression_level,
            headers=headers,
        )
        try:
            yield proxy
        finally:
            proxy.close()

    return _cm()


def rust_http_capabilities(base_url: Any = None, *, prefix: Any = None, client: Any = None, **_kw: Any) -> _Caps:
    target, headers = _target_and_headers(base_url, client)
    proxy = RustClientProxy("http", target, headers=headers)
    try:
        return _Caps(proxy._admin("capabilities")["caps"])
    finally:
        proxy.close()


def rust_request_upload_urls(
    base_url: Any = None, *, count: int = 1, prefix: Any = None, client: Any = None, **_kw: Any
) -> list:
    target, headers = _target_and_headers(base_url, client)
    proxy = RustClientProxy("http", target, headers=headers)
    try:
        return [_UploadUrl(u) for u in proxy._admin("request_upload_urls", count=count)["urls"]]
    finally:
        proxy.close()


def rust_http_introspect(base_url: Any = None, *, prefix: Any = None, client: Any = None, **_kw: Any) -> Any:
    proxy = RustClientProxy("http", base_url)
    try:
        return proxy.describe()
    finally:
        proxy.close()
