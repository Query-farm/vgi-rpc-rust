# vgi-iroh-cabi

Stable C ABI over `vgi-iroh-transport` for embedding Iroh in native VGI clients
and the DuckDB VGI extension. The library emits `staticlib` and `cdylib`; the
public interface is [`include/vgi_iroh.h`](include/vgi_iroh.h).

The ABI uses opaque handles and caller-owned buffers. Every fallible operation
returns a structured stage/category/dispatch-certainty error and contains Rust
panics. Calls may block on a single process-wide Tokio runtime. Handle free
functions must not race with operations on the same handle; cancellation may
be called while an operation is blocked.

`vgi_iroh_stream_read_timeout` is intended for synchronous hosts that need to
poll their own cancellation state. Its timeout is nonfatal. Writes deliberately
do not expose a retryable polling timeout because a timed-out `write_all` may
have already dispatched a prefix of the frame.

Tagged GitHub releases publish relocatable archives for Linux x86-64/ARM64,
macOS x86-64/ARM64, and Windows x86-64. Each is a static library suitable for a
single-artifact host such as a DuckDB extension. Windows also includes the
versioned Rust `windows-targets` import libraries required by the static link.
Each archive contains the matching header, CMake imported target with its
platform-native link dependencies, dependency license inventory, project
license files, build manifest, and a sibling SHA-256 file. The archive version
is the Rust workspace release version; hosts must also check
`vgi_iroh_abi_version()` against `VGI_IROH_ABI_VERSION` before use. These assets
begin with vNEXT.
