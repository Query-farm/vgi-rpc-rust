# Changelog

All notable changes to `vgi-rpc` (the Rust port) are listed here.

## [0.27.0] — 2026-09-23

### Added

- `vgi-rpc-client` now provides a `tcp-tls` feature and
  `RpcClient::tls_tcp_connect` for persistent VGI framing over rustls. Callers
  supply the trust roots and optional client identity; the transport enforces
  server-name verification plus bounded handshake and I/O timeouts.
- `vgi-rpc-iroh` now provides strict `IrohTarget` parsing for canonical
  `iroh://<endpoint-id>` targets and `IrohConnection::connect_uri`. Raw
  stateful Iroh remains distinct from the `httpi://` HTTP transport.

### Validation

- Added direct mTLS round-trip coverage, including rejection of the wrong
  server name and clients without a certificate.
- Added canonical Iroh-target acceptance and rejection coverage.

## [0.26.0] — 2026-09-18

Tracks the reference's identity revision of 2026-09-18
(`IDENTITY_V1_SPEC.md`: §4 "No rate limiter", §8 "Retired").

### Removed — breaking

- **`introspect_token` is no longer rate limited.** `RateLimiter`,
  `IdentityImplBuilder::introspect_rate_limit` and
  `DEFAULT_INTROSPECT_RATE_LIMIT` are gone. The limiter capped each caller at
  20 introspections a second, but the caller is the asker — a proxy
  introspecting on behalf of every client that presents a bearer — so it was
  one budget for every user's login, drainable by unauthenticated junk
  credentials, and it refused with `introspection_refused`, a kind the spec
  lets a caller negative-cache. It bounded only guessing, which a random
  credential defeats at any rate. The allowlist is the control; throttle
  untrusted traffic at the asker, per client. `introspection_refused` now means
  only "not on the allowlist". Pinned by `TestIntrospectionIsNotThrottled`
  (the conformance fixture no longer sets a limit) and by
  `introspection_is_not_rate_limited` / `a_concurrent_burst_is_answered_in_full`.
  Remove any `.introspect_rate_limit(n)` call; there is no replacement.
- **The pre-0.46 `POST {prefix}/__introspect_token__` JSON route is retired.**
  Deleted with its handler, the `vgi_rpc::auth::introspect` module
  (`TokenIntrospector`, `IntrospectOutcome`, `INTROSPECT_ENDPOINT`,
  `MAX_INTROSPECT_BODY_BYTES`), its own limiter, the `vgi-token-introspection`
  capability header, and the `HttpStateBuilder::introspect_resolver` /
  `introspect_principals` / `introspect_default_ttl` / `introspect_rate_limit`
  options. `vgi_rpc.Identity.v1` is the only introspection surface: configure
  it with `RpcServerBuilder::identity(IdentityImpl::builder()...)`, and a
  client learns whether a worker introspects from reflection. The conformance
  worker's `--introspect` flag and the harness's
  `conformance_http_introspect_port` fixture, which backed the reference's
  since-deleted HTTP-shaped group, are gone too.
- `TokenIdentity`, `TokenResolver`, `is_jws_shaped`, `token_digest` and
  `DEFAULT_INTROSPECT_TTL_SECONDS` now live in `vgi_rpc::token_identity`
  (previously defined in `vgi_rpc::auth::introspect` and re-exported there).

### Added

- `exchange_input_metadata` on the conformance worker, for the reference's
  exchange-input-metadata cases (`TestExchangeStream::test_input_metadata`,
  `TestExternalInputRoutes::test_exchange_external_input_carries_the_payloads_metadata`,
  runner case `exchange_stream.input_metadata`): one row per exchange input,
  `seen` (the value of `vgi.conformance.input`) and `keys` (the keys present,
  sorted). The server already met the contract on every transport; only the
  fixture was missing. `CallContext` offers input metadata only by key
  (`tick_metadata(key)`), so `keys` reports which of a fixed list of probe keys
  are present (every key the cases assert on plus every `vgi_rpc::metadata`
  key) rather than enumerating the batch's metadata as the reference does.
  Moves the conformance protocol hash to `4b026920…` and the method count to
  89.

## [0.25.0] — 2026-09-16

This is the multi-protocol (VGI 2.0) round. Three changes break the wire;
each is listed with what to do about it. Rust now produces byte-identical
protocol hashes to the Python reference, to Go, and to TypeScript, for all
88 conformance methods.

### Upgrade note — this port's tokens are *not* rotated, and that is the divergence

**Short version: upgrading a Rust-only deployment breaks no tokens.** Cursor,
call and sticky-session tokens minted by 0.24.4 all still open on 0.25.0, so a
rolling upgrade needs no draining of open HTTP streams or sticky sessions. Read
on only if you run a mixed-language fleet.

This is worth spelling out because the sibling ports went the other way. The
Python reference and the TypeScript port rotated their AEAD associated data in
this same window — prefixes bumped (`vgi_rpc.state.v4/v5` → `v6/v7`,
`vgi_rpc.call.v1/v2` → `v3/v4`, and sticky sessions along with them) *and* a
trailing protocol scope appended, so the break there is over-determined and
every token class is a casualty. **This port made neither change.** Verified in
source rather than assumed; all three AAD builders here are unchanged:

| Token | Builder | Prefixes (unchanged) |
|---|---|---|
| Stream cursor | `compute_aad`, `vgi-rpc/src/http.rs` | `vgi_rpc.state.v5\x00` / `vgi_rpc.state.v4\x00` |
| Call token | `compute_call_aad`, `vgi-rpc/src/http.rs` | `vgi_rpc.call.v2\x00` / `vgi_rpc.call.v1\x00` |
| Sticky session | `compute_session_aad`, `vgi-rpc/src/sticky.rs` | `vgi_rpc.session.v2\x00` / `vgi_rpc.session.v1\x00` |

(The `v5`/`v2`/`v2` spellings are the peer-evidence-bound variants; the lower
number is used otherwise.) Note that sticky sessions do **not** share an AAD
builder with the cursor and call tokens in this port — `sticky.rs` defines its
own, structurally identical but separately maintained. A port-to-port
comparison that assumes one shared builder will mis-describe this one.

No builder appends a protocol scope. `compute_aad_with` is prefix, then either
the authenticated domain and principal or the anonymous marker, then an
optional peer-evidence binding — and `compute_session_aad` mirrors it. So in
this port the separation between co-hosted protocols is enforced by the path
and the routing key, not by the AEAD tag: it is not the cryptography that
refuses a cursor replayed onto another protocol's `/exchange`. That is
unchanged from 0.24.4 rather than new, but multi-protocol hosting is what makes
it reachable, and it is the gap the reference closed by binding the protocol
into the AAD.

Two practical consequences:

- **A mixed-language fleet sharing a `token_key` can no longer resume across
  the language boundary.** A cursor, call or session token minted by a
  reference Python or TypeScript worker on the rotated AAD fails this port's
  tag check, and vice versa. It surfaces as `Malformed state token` (or
  `session_lost_error`) with nothing naming the version skew as the cause — so
  drain before mixing, or accept that in-flight continuations and sticky
  sessions restart.
- **The byte-for-byte compatibility claim in `sticky.rs`'s module docs is now
  stale.** It states that the session token format matches Python's so the two
  could validate each other's tokens given a shared key. With the reference's
  session prefixes moved, that no longer holds. The comment is unchanged in
  this release; treat it as describing 0.24.4-era Python.

### Breaking

- **`vgi_rpc.protocol` is the routing key, and it is required.** A server
  resolves the pair `(protocol, method)`; method names may collide across
  co-hosted protocols, which is what makes protocols independently
  authorable. The key is required even against a server hosting exactly one
  protocol — an exemption would let an intermediary that rebuilds a request
  and drops the field land silently on whichever protocol the server
  registered first, rather than being told.

  *Migration:* raw transports (pipe, subprocess, unix, tcp) must stamp it on
  every request — `RpcClientBuilder::protocol` / `HttpClientBuilder::protocol`
  do this for you. Over HTTP it is optional when the path carries the
  protocol, but the path segment is checked against the routing key when both
  are present, never substituted for it. Three routing failures stay
  distinct because clients depend on the difference:
  `protocol_not_specified`, `protocol_not_supported`, and the method-absent
  case, which is the documented capability-probe signal. A server built with
  no explicit `protocol_name` now defaults to `"Service"` (it previously
  carried an empty one, which under a required routing key would make it
  unreachable) — set one explicitly if you rely on the name.

- **`__describe__` is retired; introspection is `vgi_rpc.Reflection.v1`.** No
  server answers `__describe__`, and `RpcServerBuilder::enable_describe` is
  gone along with the `vgi_rpc::introspect` module. A `__describe__` request
  is refused with a message naming the replacement protocol and both of its
  entry points, rather than a generic "unknown method" — the generic answer is
  indistinguishable from "this server was built without introspection", and
  the two need opposite fixes.

  *Migration:* call `list_protocols` for what a server hosts, then `describe`
  for one protocol's methods — `RpcClient::list_protocols` /
  `describe_protocol` and their `HttpClient` counterparts. `describe()` is two
  round trips; name a protocol to skip the first. Reflection is handled
  *before* the version gate, because it is what a version-mismatched client
  calls to learn what mismatched.

- **The protocol hash is redefined; every pinned digest moves.** It used to be
  taken over serialized Arrow IPC bytes, which are not stable across Arrow
  implementations — so `protocol_hash` was advisory and comparable only against
  itself. The preimage is now canonical JSON (RFC 8785 / JCS) of the decoded
  description:
  `sha256("vgi_rpc.protocol_hash.v1|" + canonical_json(description))`. Every
  number folds into a type token (`decimal128(38,9)`), so JCS's number rule —
  the likeliest place for six ports to diverge — never applies. Not in the
  preimage: server identity, docstrings, parameter defaults, language-specific
  type names, framework request/describe versions, and `stream_kind`.

  *Migration:* re-read any digest you have pinned; none of the old values
  survive. `type_token` is total — an unrecognised Arrow type is an error, not
  a fallback to `DataType`'s `Display`, whose output is an arrow-rs
  implementation detail no other port shares. Two consequences worth knowing:
  arrow-rs's `Decimal32`/`Decimal64` are spelled following the same pattern but
  cannot be expressed in ports whose Arrow lacks them, and arrow-rs carries no
  `ordered` flag on `Dictionary`, so an ordered dictionary from another port
  decodes as unordered here and the hashes differ — visibly, which is the
  correct outcome.

### Fixed

- **The byte-stream client resolved no external-location pointers at all.**
  `read_substream` and the stream session matched three envelope kinds — log,
  exception, data — with no pointer arm, so an externalized batch classified as
  data and reached the caller as a zero-row batch. Silent row loss on every
  externalized batch over pipe, subprocess, unix and tcp, and an empty result
  is not an error anywhere. Externalization is not an HTTP feature
  (WIRE_PROTOCOL.md §12): resolution now happens on the unary result, the
  stream header, and every stream turn, through one path that also dispatches
  the log batches bundled into an externalized cycle. `RpcClient` gains
  `external_resolution`, `external_resolution_any` and `external_config`; a
  pointer arriving at a client with no resolver is now a named error rather
  than an empty batch, which is the failure a caller can act on.

- **A stream header is externalizable, and its pointer is zero-row.** Four of
  seven ports classified that zero-row batch as a log *before* testing for
  `vgi_rpc.location`, skipped it, and then reported the header absent — it does
  not fail to parse, it fails to exist. `classify` now tests for the pointer
  first, and `BatchKind` carries a `Pointer` variant so every reader in this
  crate has to decide what to do with one rather than fall through to `Data`.
  This is the one resolution path a port cannot exercise against itself: this
  crate's server writes its header batch directly and externalizes only in the
  data path, so the guard test drives a hand-rolled peer that externalizes a
  header, and the cross-language client leg drives the reference, which does.

- **The resolver stamps both provenance keys, not one.** §12 makes
  `vgi_rpc.location.source` — the URL that was actually fetched — as much the
  reader's responsibility as `vgi_rpc.location.fetch_ms`, and this port stamped
  only the latter: what you get from implementing the first of the pseudocode's
  two adjacent assignments. A resolved batch carrying neither key is
  indistinguishable, to a correct peer, from one whose resolver silently did
  not run. Both are now stamped in one place,
  `vgi_rpc::external::resolved_metadata`, which every reader here calls; a
  pointer on the wire carries neither, and a writer that supplies either has it
  stripped rather than propagated as a URL nobody fetched.

- **The HTTP client addresses methods on the protocol-qualified path.**
  `HttpClient` posted every call to a bare `/{method}`, which the reference
  Python server does not route -- it serves only `{protocol}/{method}`, so
  every unary, `/init` and `/exchange` came back `404 {"title": "404 Not
  Found"}` and surfaced as an IPC framing error when the JSON body was read
  as Arrow. The path now carries the bound protocol as its first segment
  (`HttpClientBuilder::protocol`); a client with no protocol bound still
  sends the bare path, which is all it can do. Rust servers route both
  shapes, which is why the Rust-to-Rust matrix never saw this and only the
  cross-language client leg did.

- **`vgi_rpc.Reflection.v1` describes its own two methods.** The binding was
  registered without them, so `describe("vgi_rpc.Reflection.v1")` returned an
  empty method list and the protocol hashed to `fafffd66…` instead of the
  reference's `3c7db4ca…`. A client discovering a server the documented way —
  `list_protocols`, then `describe` — was told reflection exists and then told
  it has nothing to call, so it could not learn to call the protocol it was
  already calling. Nothing local could see it: `list_protocols` advertised the
  same digest this port's own `describe` returned, and only a port-to-port
  comparison disagreed. Dispatch is unchanged — reflection already answered
  both methods — and the digest is now pinned, with its shape, by
  `reflection_self_description`. Reflection's hash moves; the application and
  `vgi_rpc.Identity.v1` digests do not.

- **Access records carry the owning binding's protocol *and* hash.** Both
  fields now come from `RpcServer::protocol_identity`, read off the binding a
  request routes to, so a co-hosted protocol's calls are no longer filed under
  the application's identity. This failed silently: a mislabelled record is
  well-formed, passes the schema, and feeds a plausible dashboard while a
  consumer keying on `protocol_hash` decodes it against the wrong description.
- **`protocol_hash` is the canonical digest.** The access log published the
  digest the retired `__describe__` payload carried, which hashed serialized
  Arrow IPC bytes — bytes each language may legitimately spell differently for
  the same logical schema, so an archived record could not be keyed against the
  canonical registry at all.
- Reflection calls now produce access records; previously they produced none,
  on any transport.
- `sentry_sdk.rs` compiles again under `--all-features`. `RpcError::traceback`
  narrowed to `Box<str>` in the identity round; this site is reachable only
  with the `sentry-sdk` feature, so nothing in a default build compiled it.
- `access_log_identity` and `http_identity` declare `required-features =
  ["http"]`, so a narrow-feature build skips them instead of compiling tests
  whose imports were configured out.
- **HTTP streams emit access records.** Previously neither `/init` nor
  `/exchange` fired a dispatch hook, so a deployment serving streams over HTTP
  had a hole in its log covering the calls that run longest and move the most
  data. One record per turn now, all sharing the `stream_id` minted at `/init`
  and carried in the call token — so a continuation handled by another worker
  still files under the call it belongs to. `request_data` on the init record
  only; `response_state` (the decrypted cursor) while the stream is resumable
  and absent on the terminal turn. A port that emits *nothing* here passes
  every record validator, because a validator validates the records that
  exist.
- The conformance worker's `AllTypes::to_record_batch` built columns in the
  pre-reorder order while `all_types_schema()` declared the corrected one, so
  every column from index 14 on was one position out and the batch was
  rejected. The schema is unchanged; the protocol hash does not move.
- `tcp_serve`, `inproc_roundtrip` and `loopback` stamp `vgi_rpc.protocol` on
  their requests. All three predate the routing key and were being refused
  before dispatch.

### Changed

- `scripts/conf.py` resolves the Python reference from `VGI_RPC_PYTHON_REPO` /
  `VGI_RPC_PYTHON` (defaulting to `~/Development/vgi-rpc-python`) instead of a
  hardcoded path to `~/Development/vgi-rpc`, which is `main` and carries none
  of the multiservice work despite a numerically higher version. It prints the
  reference's git revision on every run — a failure count is a measurement of a
  reference, and the reference moves — and warns when the interpreter's
  `vgi_rpc` does not live under the checkout under test, because an installed
  wheel is a pin too.
- `--timeout` / `--per-test-timeout` are defaults rather than clamps. The 59s
  cap meant a suite that had outgrown it could only ever report
  `OVERALL TIMEOUT`.

### Added

- **`vgi_rpc.Reflection.v1`**, a co-hosted protocol with `list_protocols` and
  `describe`, routed by the same key as everything else and appearing in its
  own output. Payloads are generated schemas mirroring the reference field for
  field, returned as a nested IPC stream in the framework's ordinary `result`
  binary column. Reaching cross-port agreement on the digest exposed four real
  defects nothing could have detected before: `echo_enum` accepted a dictionary
  and answered a plain string; the rich header schema declared `nested_list` in
  the wrong position; `MethodEntry` declared its fields in a plausible rather
  than sorted key order, putting every digest off by a constant; and a
  `ListBuilder` inside a `StructBuilder` was downcast to its concrete element
  type, panicking mid-response and reaching the client as a truncated stream.

- **`vgi_rpc.Identity.v1`** — resolving an opaque credential to a principal
  (`introspect_token`) and minting a standing grant (`issue_grant`), as a
  framework-owned protocol rather than an HTTP route. The route form (`POST
  {prefix}/__introspect_token__`) is still served, but it existed on one
  transport only and had to be hand-written in every port; as a protocol it
  routes, reflects and hashes like everything else. The two methods are guarded
  deliberately differently: `introspect_token` answers a question about
  *somebody else's* credential, so it takes an allowlist with no permissive
  default, uniform rejections, a JWS-shaped subject refused before the resolver
  runs, and a rate limit — with the guard order load-bearing, authorization and
  rate limit preceding any look at the subject, including how long looking
  took. `issue_grant` mints for the *calling* user, so it has no allowlist, no
  rate limit, actionable rejections, and no subject parameter at all —
  cross-subject minting is closed by construction. Requiring an `auth_time`
  claim stops a grant minting another grant, and makes subprocess/unix fail
  closed for free. The credential cap is measured in UTF-8 bytes.


- `produce_annotated_batches` on the conformance worker — a producer emitting
  `count` batches that carry a varying `conformance.batch_index`, a constant
  `conformance.batch_total`, and a deliberately non-ASCII
  `conformance.emit_label`. It pins the one point where per-emit metadata meets
  externalization, which no conformance method reached before because none
  emitted per-batch custom metadata. Moves the conformance protocol hash to
  `7713e810…` and the method count to 88.
- `conformance_bytestream_external_target`, the fixture backing the shared
  `TestExternalByteStream` group, plus `--fake-storage <url>` /
  `--externalize-threshold <n>` on the conformance worker's byte-stream
  transports. The group *fails* rather than skips for a runner that supplies
  external storage and withholds this fixture, because withholding is how the
  byte-stream half of a pointer resolver stays untested.
- `RpcClient::list_protocols` / `describe_protocol`, and their `HttpClient`
  counterparts. `describe()` is two round trips (`list_protocols`, then
  `describe`); name a protocol to skip the first.
- `POST {prefix}/{protocol}/{method}` addresses a unary method by the protocol
  that owns it. The bare `/{method}` route cannot reach reflection's `describe`,
  which collides with the human-facing describe *page*.
- `POST {prefix}/{protocol}/{method}/init` and `/exchange` do the same for
  streams — the path shape the reference client builds every request from. The
  path segment is checked against the request's routing key, never substituted
  for it.
- `DispatchInfo::response_state`, the decrypted outbound stream cursor, for the
  access log's `response_state` field.
- `a_dispatch_record_may_only_be_built_by_the_one_constructor` — a companion to
  the existing identity guard, which scans for *assignments* and so cannot see
  an emit site that sets the identity fields to nothing at all. Outside
  `hooks.rs`, a `DispatchInfo` may only come from `from_request`.
- The two `vgi_rpc.Identity.v1` conformance fixtures, so the shared cross-port
  group runs instead of skipping: `--identity both` and `--identity
  introspect-only` on the conformance worker, exposed to the harness as
  `conformance_http_identity_port` and
  `conformance_http_identity_introspect_only_port`. Policy — allowlist,
  `max_auth_age`, rate limit, and the two hooks — is pinned by
  `IDENTITY_CONFORMANCE_FIXTURE.md` and transcribed in the worker's
  `identity_fixture` module; the plain worker deliberately configures no hook,
  because the group asserts against *it* that a deployment configuring none
  hosts no identity protocol at all. Authentication is two request headers
  (`X-Conformance-Principal`, `X-Conformance-Auth-Time`, the latter verbatim
  into `claims["auth_time"]`) — trivially spoofable, a test fixture, never to
  be deployed. All 77 cases pass, including the byte-measured credential cap
  the group expects codepoint- and UTF-16-measuring ports to fail. Mutation-
  checked against all twenty breakages the contract's §8 lists: twenty killed,
  none survived.

## [0.24.4] — 2026-09-11

### Added

- Let supervisors provide the bridge's persistent Iroh secret through inherited
  standard input without placing it on disk, and zeroize the encoded key after
  parsing.
- Add machine-readable bridge discovery output containing the EndpointId,
  relay URLs, and direct addresses.

### Changed

- Log routine client-initiated raw-stream shutdown at debug level while keeping
  connection, admission, identity-preamble, and task failures at warning level.

## [0.24.3] — 2026-09-05

### Added

- Publish `vgi-iroh-bridge` executable archives for Linux, macOS, and Windows
  with checksums and release provenance.
- Publish a Linux x86-64/ARM64 bridge container to
  `ghcr.io/query-farm/vgi-iroh-bridge` from the same tested binaries.

### Changed

- Consume the released `query-farm-iroh-http-core` package instead of an
  internal Git revision.
- Separate HTTP request-head and streaming body-idle protection from the
  optional worker execution deadline, and remove the implicit bridge request
  body ceiling.

## [0.24.2] — 2026-09-05

### Fixed

- Browser clients normalize trailing DNS root dots in both configured and
  discovered Iroh relay URLs, avoiding WebKit TLS certificate rejection while
  preserving authenticated pkarr discovery and the selected relay hosts.

## [0.24.1] — 2026-09-04

### Added

- Installable `@query-farm/vgi-rpc-iroh-browser` WebAssembly package for
  browser `vgi-rpc/arrow-mux/1` and `iroh-http/2` clients, including the
  Haybarn SharedArrayBuffer adapter and custom or disabled relay selection.
- Shared C ABI libraries in every native release archive so managed-language
  packages can load the embedded Iroh transport at runtime as well as C and
  C++ consumers linking it statically.

## [0.24.0] — 2026-09-04

### Added

- Provider-neutral peer identity and authentication composition for direct
  Iroh peers, Tailscale, trusted PROXY-v2 listeners, forwarded HTTP identity,
  and proxy-verified SPIFFE workloads.
- Native `iroh://` Arrow-mux and `httpi://` HTTP-over-Iroh clients, including
  the reusable `vgi-iroh-transport` core and stable `vgi-iroh-cabi` embedding
  surface.
- A narrow dual-protocol Iroh bridge for existing raw and HTTP VGI workers. It
  preserves cryptographic Iroh identity while leaving load balancing and
  authorization to the configured upstream deployment.
- Browser WebAssembly bindings and a Haybarn demonstration for raw Arrow mux
  and HTTP-over-Iroh. Generated bindings are exercised in Chrome, Firefox, and
  WebKit, with an explicit Apple Safari qualification path.
- Strict HTTP response-budget negotiation across unary calls and continuation
  turns, separating client acceptance, worker production, and hosting limits.

### Changed

- The release workflow now builds relocatable C ABI archives for Linux, macOS,
  and Windows, validates them with installed-package consumer smoke tests, and
  publishes the typed native and browser Iroh crates in dependency order.

### Fixed

- Iroh bridge admission, cancellation, shutdown, idle-connection, and drain
  behavior is bounded without expiring active raw streams.
- Forwarded Iroh and Tailnet evidence cannot bypass the configured trusted
  proxy boundary or silently downgrade invalid application credentials.

## [0.23.3] — 2026-08-27

### Fixed

- Subprocess clients can enforce a monotonic response deadline per RPC. An
  expired call poisons the connection so late pipe bytes cannot desynchronize a
  later call or return the client to a pool. Unix kills and reaps the worker's
  private process group before joining its reader. Other platforms kill and
  reap the direct child, then bound the reader join and detach it if a
  descendant retained stdout.
- Synchronous unary, stream-init, producer, exchange, cancellation, state
  decode, and state-encode callbacks no longer occupy Tokio HTTP workers on a
  multi-thread runtime. Slow worker code now yields async request capacity via
  `block_in_place`, so unrelated requests and post-timeout recovery continue
  immediately even on a one-worker runtime.

## [0.23.2] — 2026-08-24

### Performance

- Non-dictionary shared-memory batches now decode directly from mmap-backed
  Arrow buffers while retaining stock crates.io `arrow-rs`. Allocator slots
  remain owned until the final array view is dropped, avoiding both the inbound
  payload copy and premature slot reuse.
- Shared-memory serialization now uses the direct single-row `LargeBinary`
  writer introduced in 0.23.1, and allocator entries preserve Arrow IPC
  alignment between consecutive batches. On the canonical Linux benchmark,
  16 MiB echo latency fell from 11.91 ms to 9.56 ms (3.27 GiB/s), making shared
  memory 14% faster than the 11.12 ms Unix-socket result.

## [0.23.1] — 2026-08-24

### Added

- `LargeBytesBuffer` provides an immutable, reference-counted `LargeBinary`
  handler value. Reading retains a slice of the inbound Arrow allocation and
  returning it transfers that buffer into the response array without copying.

### Performance

- `LargeBytes(Vec<u8>)` response construction now transfers the vector's
  allocation directly into Arrow instead of copying it through a builder.
- Single-row `LargeBinary` batches write their value buffer directly to the
  destination pipe, socket, HTTP body, or shared-memory serializer. This avoids
  the additional payload-sized staging vector created by arrow-rs's general IPC
  encoder while retaining canonical Arrow IPC framing and custom metadata.
- The conformance worker's `echo_large_binary` method uses the zero-copy type.
  Controlled local 16 MiB echo latency improved from 11.36 ms to 7.52 ms over
  Unix sockets and from 14.13 ms to 10.07 ms over loopback TCP, with small-call
  latency unchanged.

## [0.23.0] — 2026-08-23

### Added

- HTTP workers now encode gzip responses as well as zstd and advertise the
  mandatory `zstd, gzip` pair. The Rust HTTP client advertises both codecs and
  decodes gzip responses with the same encoded and decoded size bounds used
  for zstd.
- Producer ticks can carry application metadata through raw and HTTP clients,
  including continuation turns handled by the native conformance bridge.
- TCP, shared-memory, raw-adversarial, and same-connection stream-init recovery
  now participate in the normal shared conformance matrix.
- Recursive container serialization covers enums and Arrow dataclasses inside
  lists, maps, sets, and tagged unions, with protocol-version enforcement at
  dispatch.

### Changed

- HTTP producer requests are strictly lock-step: one request invokes the
  producer state exactly once and may return at most one data batch. Response
  byte caps size that turn but never authorize coalescing later turns.
- The conformance client preserves native continuation tokens and correctly
  distinguishes metadata-only token sentinels from zero-column data batches.

### Performance

- **A Unix socket got 8 KiB of kernel buffer, and so ran at half the pipe's
  throughput.** macOS defaults `net.local.stream.sendspace` to 8192 bytes —
  against ~64 KiB for a pipe — so a megabyte of Arrow crossed the kernel in 128
  trips instead of a handful. `unix::widen_socket_buffers` now requests 1 MiB,
  and `serve_unix` and `vgi-rpc-client`'s `UnixTransport::connect` both call it.

  Both ends have to: an `AF_UNIX` write is bounded by space in the *receiver's*
  buffer, so a tuned server still feeds an untuned client 8 KiB at a time.
  Fixing only the client end, against an already-tuned C++ worker, took echo
  throughput from 4,994 to **18,597 MB/s** at a 1 MiB payload (3.7x), 2,613 to
  4,438 at 64 KiB, and 2,373 to 5,369 at 16 MiB. The pipe control column moved
  3% across those runs, so that is the change rather than the machine.

  `TcpTransport` deliberately does not get the same call: TCP already starts at
  128 KiB and grows, an explicit `SO_RCVBUF` *disables* Linux's receive-window
  auto-tuning and pins the window at whatever constant we guessed, and an A/B
  on loopback showed no gain either way.

  Adds `socket2` as a `cfg(unix)` dependency of `vgi-rpc` and `vgi-rpc-client`.

### Fixed

- Stream initialization failures remain typed and leave persistent raw
  connections reusable.
- HTTP response parsing rejects genuinely coalesced data batches without
  rejecting a valid zero-column batch followed by a continuation sentinel.

- The conformance harness imported `httpx`, which the Python reference no
  longer installs — it moved to the `httpx2` fork. `test_rust_conformance.py`
  now accepts either, so collection stops failing before any test runs.

## [0.22.0] — 2026-08-14

### Fixed

- **A field named with a Rust keyword reached the wire with its `r#` prefix.**
  `#[derive(VgiArrow)]` took each column name from `Ident::to_string()`, which
  keeps the raw-identifier marker: a field that has to be spelled `r#type`
  produced an Arrow column literally named `"r#type"`. The VGI protocol has
  such a column — `catalog_schema_contents_functions` and `_macros` carry a
  `type` selector — so those methods could not be called by a Python, C++ or Go
  peer, which all send `type`. The prefix is now stripped on both the schema and
  the array-building path, matching how serde and the rest of the ecosystem
  treat raw identifiers.

- **Map columns used arrow-rs's child names rather than the protocol's.** The
  `Vec<(String, V)>` implementation built its entries struct as
  `keys`/`values` — arrow-rs's `MapBuilder` default — where pyarrow, the
  canonical Python protocol, the C++ extension and the Go worker all use
  `key`/`value`. Any map-valued field (`tags`, `options`, `estimated_object_count`)
  therefore went out with non-canonical child names. The read path was already
  positional, so only what is written changes.

### Wire compatibility

Both fixes change bytes on the wire, which is why this is a minor bump rather
than a patch. Both move Rust *toward* the canonical Python protocol, so a Rust
worker talking to a Python, C++ or Go peer is strictly more correct after
upgrading — one of the two methods above did not work at all before. A
Rust-to-Rust pair is unaffected in the map case, since that decoder reads
entries positionally.

## [0.21.1] — 2026-08-13

### Changed

- **The logo is transparent.** Both copies of the mark — `assets/vgi-logo.png`,
  which the crate READMEs link, and the `data:` URI inlined in the landing page
  `vgi-rpc` serves — were the old export on a white background with no alpha, so
  both wore a white rectangle wherever the page behind them was not white. Both
  are now cut from a committed master by `scripts/regenerate_logo_assets.py`.
  The inlined copy is palettized to 256 colours, which for flat artwork is
  visually indistinguishable from truecolour and holds the base64 compiled into
  every dependent binary at 20 KiB rather than 99 KiB.

No API or wire change; this is a patch.

## [0.20.0] — 2026-08-05

### Added

- **Access log: trace correlation.** Records carry `trace_id` / `span_id` as
  W3C hex when a valid span is current. `request_id` only joins records within
  one service, so without these a log line and the span describing the same
  call cannot be matched. The ids are read from whatever span is *current*,
  via a provider installed with `access_log::set_trace_context_provider`, so an
  application-opened span correlates as readily as a framework-opened one —
  and so the core keeps no OpenTelemetry dependency (the `otel` feature is
  tracing-only). Ids that are not 32 / 16 lowercase hex, or are all zeroes, are
  dropped rather than emitted, and the pair is always emitted together or not
  at all.
- **Access log: sampling.** `AccessLogHook::with_sample_rate(rate)`. Errors are
  never sampled — a rate below 1 exists because successes repeat, which
  failures do not. The decision is deterministic and keyed on `stream_id`, then
  `request_id`, so every record of one stream shares its init's fate rather
  than being shredded into fragments indistinguishable from data loss. Every
  kept record carries `sample_rate`, because a consumer scaling counts has to
  divide by it. An out-of-range rate is an error at construction, not at the
  first request.
- **Access log: egress accounting.** `request_bytes` (on-wire, before
  decompression), `response_bytes` (on-wire, after compression) and
  `externalized_bytes` (uploaded to external storage). Distinct from
  `input_bytes` / `output_bytes`, which measure logical Arrow buffers and can
  differ by a factor of a thousand on a compressible body. `response_bytes`
  cannot be measured where the others are — compression runs after the handler
  — so emission is deferred through a `hooks::AccessSink` that the HTTP
  post-processing middleware drains once the final body exists. A transport
  that installs no sink keeps logging inline.
- **Access log: claim redaction.** `claims` are now emitted, redacted by key
  (credentials plus the standard OIDC personal-data claims). Values are
  replaced rather than dropped, so which claims a credential carried stays
  answerable. `AccessLogHook::with_claim_redactor` replaces the policy;
  `access_log::no_redaction` opts out for a service that owns its logs end to
  end. A redactor that panics fails **closed** — the claims are dropped, never
  emitted raw.
- **Access log: `dropped_records`.** The bounded async queue already dropped
  rather than blocked; the loss is now reported in-band on the next record
  through, so a consumer can tell a quiet period from a lossy one.
- **Access log: per-record size cap.** `AccessLogHook::with_max_record_bytes`
  (default 1 MiB) sheds `request_data`, then `claims`, then everything but the
  required envelope (`truncated: "record_too_large"`). `error_message` is never
  truncated.
- Conformance worker: `--access-log-sample`, `--access-log-async`,
  `--access-log-queue-size`, `--access-log-max-record-bytes`.
- Conformance worker: `--access-log-debug` (DEBUG-equivalent verbosity, i.e.
  `AccessLogHook::with_verbose`), and CI now runs `vgi-rpc-test --access-log
  ... --require-request-data` against it. Validated at INFO the log simply
  never carries `request_data`, so every rule governing the field was
  satisfied vacuously — and the check itself was manual, which is how the
  contract drifted with four people having inspected it.

### Changed

- **Access log: `truncated` disambiguated.** A record that omits the request
  payload because this level does not log payloads now reports
  `"payload_omitted"`; `true` again means genuine size-driven shedding. The
  two shared one value, which fired on essentially every record and left a
  consumer scanning for real data loss with nothing to filter on.
- HTTP unary records now carry the request payload's size and the omission
  marker (previously neither, which failed the schema's "unary requires
  `request_data` unless truncated" rule for every HTTP record).
- `hooks::DispatchInfo` gains `request_bytes`, `externalized_bytes` and
  `access_sink`, and now implements `Default` so a later field addition does
  not break struct literals.

### Fixed

- **Payloads over 2 GiB survive the unix and TCP transports.** `impl Write for
  &UnixStream` / `&TcpStream` hand the full length to `send(2)` without the
  `INT_MAX` clamp `std`'s file-descriptor writer applies, so on macOS a >2 GiB
  Arrow IPC body died with `EINVAL` on both socket transports (pipes were
  already fine). Every write out of `wire::StreamWriter` is now clamped to
  1 GiB, which covers the transports the crate ships *and* a worker that hands
  `serve` a socket of its own. Linux hides the whole class — it caps a single
  transfer at `0x7ffff000` and returns a short count `write_all` absorbs — so
  the Linux CI could not have found this.
- **`wire::MAX_IPC_MESSAGE_BYTES` no longer caps legitimate payloads at
  256 MiB.** It was doing two jobs: refusing an absurd `bodyLength` before
  allocating on it, and — incidentally — imposing a hard size limit the Python
  reference does not have, which made a >2 GiB round-trip a conformance
  failure. The anti-OOM job now belongs to the reader, which buffers a body
  from the bytes that actually arrive rather than from the claim, so a crafted
  length costs a few MiB and an EOF. The ceiling moves to `u32::MAX`.

## [0.17.0] — 2026-07-27

### Added

- **Proxy proof** (`auth::proof`, feature `http`): a worker can refuse any
  request that did not arrive through a trusted proxy, by recomputing an
  HMAC-SHA256 over a timestamp, a nonce and the worker's own identifier
  against a secret shared only with that proxy. Unlike a forwarded assertion
  about what happened at a TLS terminator, a proof cannot be produced by
  someone who merely reaches the worker directly — without the secret there is
  nothing to replay.
  - `proof_authenticate(cfg, inner)` composes as an **AND**. It is deliberately
    not passed to `chain_authenticate`, whose first-non-anonymous-wins
    semantics would let a later credential bypass it.
  - `NonceCache` is bounded by capacity as well as TTL: a TTL bounds how long
    an entry lives, never how many arrive inside the window, so TTL-only would
    be a remote memory-exhaustion vector.
  - No new dependency — `hmac` and `sha2` were already in the tree, and
    `Mac::verify_slice` is constant-time internally.
  - Verified against golden vectors minted by the Python reference
    implementation: this port both verifies its tokens and mints byte-identical
    output, which is the only check that catches a canonical string framed
    differently from the other languages.
  - `HttpStateBuilder::proxy_proof_required(true)` advertises the
    `VGI-Proxy-Proof-Required: true` capability header (and CORS-exposes it) on
    every response, so a proxy can tell an enforcing worker from one silently
    ignoring the header — the misconfiguration that makes the feature a no-op.
    Advertisement only: the gate arrives through `authenticate` as an opaque
    callback the builder cannot introspect, so the operator states the posture.
    Emitted only for `require`; `allow` never denies, so it must not claim to.
  - `--http-proof` on the conformance worker; the shared `TestProxyProof` group
    (22 cases) runs against this port.

  Contract: `docs/proxy-proof-spec.md` in vgi-rpc.

## [0.16.0] — 2026-07-21

- **Fixed (http)** `max_body_size` is now actually enforced. axum installs a
  2 MiB `DefaultBodyLimit` on every route and checks it *before* our
  `RequestBodyLimitLayer`, so the configured ceiling — including the
  documented 64 MiB default — was silently inert above 2 MiB and every larger
  request body got a 413. Measured against a stock worker: 4 MiB was rejected
  before, accepted now; 80 MiB is still rejected against the 64 MiB ceiling.
  Found by a benchmark with realistic (incompressible) Arrow payloads, which
  produce ~4.4 MiB compressed exchange bodies; the previous benchmark payload
  compressed ~1242x, so bodies never approached the limit.
- **Changed (MSRV)** minimum supported Rust version raised 1.90 → 1.97.

## [0.15.0] — 2026-07-21

- **Changed (http, default)** zstd response compression is now **on by
  default** at level 1 (`DEFAULT_RESPONSE_COMPRESSION_LEVEL`), matching the
  Python SDK's `compression_level=1`. Level 1 measured 4.7x faster than
  level 3 *and* produced a smaller body on an 8.41 MB Arrow payload, so this
  is not a size/speed trade. A stock server therefore advertises
  `VGI-Supported-Encodings: zstd` and actually compresses.
- **Added (http)** `HttpStateBuilder::disable_response_compression()` — the
  explicit opt-out now that the default is on.
  `response_compression_level(n)` only changes the level.
- **Fixed (http)** capability (`VGI-*`) headers are now attached to
  compressed responses. The compressed early-return path skipped
  `attach_capability_headers`, so every compressed Arrow body arrived
  without a single capability header.
- **Fixed (http, CORS)** `Access-Control-Expose-Headers` now lists every
  `VGI-*` capability header the server emits (plus `X-VGI-Content-Encoding`,
  `X-VGI-RPC-Error`, and the sticky-session headers). Previously it named
  only `Content-Encoding` / `WWW-Authenticate`, so a browser `fetch()`
  client could not read a single server capability.
- **Fixed (client)** `VGI-Supported-Encodings` absent and present-but-empty
  are no longer conflated. Absent means a legacy server (assume `zstd`);
  present-but-empty means the server speaks no compression, and the client
  now stops sending compressed request bodies instead of eating a 415.

## [0.14.2] — 2026-07-19

- **Docs** fixed all rustdoc intra-doc-link warnings across `vgi-rpc` and
  `vgi-rpc-client` (broken/renamed/private links and an ambiguous
  `axum::serve` reference), so `cargo doc --all-features` builds clean and
  the affected items render as proper links on docs.rs. No code changes.

## [0.14.1] — 2026-07-19

- **Docs** added the Vector Gateway Interface logo to the repository and
  crate READMEs (referenced by absolute URL so it renders on both GitHub
  and crates.io). No code changes.

## [0.14.0] — 2026-07-19

Headline: **hot-path allocation reductions** across server dispatch, the
Arrow-IPC wire writer, and the HTTP transport. No cross-language wire
change — the full 901-test conformance suite stays green on every
transport.

- **Changed (API)** `Request.metadata` is now `Arc<Metadata>` (was
  `Metadata`). Reads via deref (`req.metadata.get(...)`, `&req.metadata`)
  are unaffected; the field is now shared with `CallContext` /
  `DispatchInfo` by `Arc` bump instead of two deep hashmap clones per
  request.
- **Performance (dispatch)** the `DispatchInfo` build and the request
  batch re-serialization now run only when a dispatch hook is registered,
  so the hookless path skips a full Arrow re-encode and a large
  owned-clone struct per request. Roughly halves unary-noop allocations.
- **Performance (streams)** per-tick input metadata is moved into the
  context instead of deep-cloned; `cast_batch` reuses the caller's
  `SchemaRef` instead of deep-cloning the `Schema`; the zero-row envelope
  batch is built once per stream; and a reusable, lazily-allocated
  `EnvelopeMeta` builds log/error envelope metadata without rebuilding
  the map (or re-stringifying the ids) per line — and allocates nothing
  on calls that never log.
- **Performance (wire)** `StreamWriter` reuses one `FlatBufferBuilder`
  for the per-batch metadata repack and drops the two throwaway
  descriptor `Vec`s (`create_vector_from_iter`); `parse_custom_metadata`
  pre-sizes its map.
- **Performance (http)** stream continuations reuse the schema bytes
  already carried in the token instead of a decode→re-encode of both
  schemas every turn; the post-processing middleware extracts only the
  header values it needs instead of cloning the whole request
  `HeaderMap`; capability + CORS response headers are precomputed once at
  build time.
- **Changed (http)** zstd response compression now skips bodies below a
  1 KiB threshold and keeps the compressed form only when it is actually
  smaller, so tiny error / continuation-token responses ship
  uncompressed. (`Accept-Encoding` is a client capability, not a demand,
  so this is transparent to conformant clients.)

## [0.13.0] — 2026-07-16

Headline: **shm request-batch resolution**, **HTTP exchange metadata parity
with the Python reference**, and **continuation-only stream resume** on the
client.

- **Fixed (shm)** shm-routed *request* batches now resolve against a
  per-connection segment cache (attach-from-request-metadata when the cache is
  empty); responses route through shm only when the request signalled shm this
  exchange. Mirrors vgi-rpc-python 42701df.
- **Fixed (http)** the init request's custom metadata now reaches a producer's
  first tick (`CallContext::tick_metadata`), so result-cache conditional
  revalidation (`vgi.cache.if_none_match` / `if_modified_since`) fires over
  HTTP. Parity with the Go/Java/TS ports.
- **Added (client)** continuation-only stream resume:
  `HttpClient::resume_stream`, `HttpStreamSession::next_with_token` /
  `seek_to_token` — resume a producer stream from a relayed token without a
  bind/init round-trip.
- **Fixed (wasm)** the crate builds on `wasm32-wasip2` again with `shm`
  enabled: `windows-sys` is target-gated to Windows, the proc-macro decoders
  are gated on `stream-codec` (not `http`), and the shm module gained a
  fallback backend (create/attach return `NotImplementedError`) for platforms
  with neither POSIX shm nor Win32 sections.

## [0.7.0] — 2026-06-26

Headline: the crate now **builds for `wasm32-wasi`** (a VGI worker can be
compiled to WebAssembly and served over stdio/TCP under a WASI runtime), with
no change to native builds.

- **Added** a lightweight `stream-codec` feature (serde + bincode only, no
  server stack) and moved `stream_codec` behind it instead of `http`. The core
  dispatch path uses `stream_codec`, so it must be available without the
  axum/tokio HTTP stack (which does not compile to wasm). `http` re-includes it.
- **Fixed** `std::process::id()` aborting on `wasm32-wasi` ("no pids on this
  platform"): `access_log::random_stream_id` and the unary id helper fall back
  to `0` under `cfg(wasm32)` — time + counter already disambiguate within the
  single wasm process.

## [0.6.0] — 2026-06-26

Headline: a **raw-TCP socket transport** — the network analog of the existing
Unix-socket transport, speaking the same raw Arrow-IPC framing without the HTTP
envelope.

- **Added** `serve_tcp` (server) and `TcpTransport` + `RpcClient::tcp_connect`
  (client), plus `TransportKind::Tcp`. Binds loopback (`127.0.0.1`) by default;
  `port 0` auto-selects. `TCP_NODELAY` enabled; optional idle self-termination
  mirroring the Unix serve loop. **No auth/TLS** — trusted networks only; use
  HTTP otherwise.
- The conformance worker gains `--tcp [HOST:]PORT`, emitting a
  `TCP:<host>:<port>` discovery line. Verified at full conformance parity with
  the `--unix` baseline via the Python `vgi-rpc-test --tcp` harness.

## [0.3.0] — 2026-06-18

Headline: a new **`vgi-rpc-client`** crate — a blocking, dynamic, schema-first
client for the canonical wire protocol — validated by running the Python
reference conformance suite against it across pipe / subprocess / unix / HTTP /
shm, driving the Rust, Python, and Go conformance servers.

- **Added** the `vgi-rpc-client` crate. `RpcClient` (unary / producer /
  exchange / cancel / `describe` / `transport_options`) over the byte-stream
  transports (subprocess, AF_UNIX, pipe, shm) plus an `HttpClient`. HTTP
  production surface: transparent external-location resolution, sticky sessions
  (with a session stack for nesting), 413 request-externalization via vended
  upload URLs, 415/zstd request-codec negotiation, a default request timeout,
  and connection-level retry on idempotent calls (never on `exchange`). The
  lockstep stream session opens its output reader lazily so it is compatible
  with both the Rust server (writes the output schema first) and the Python
  server (reads the input schema first). Native tests cover in-process
  round-trips and HTTP fault injection (timeout / retry / garbage responses).
- **Added** a lightweight `external` cargo feature on `vgi-rpc` (zstd only, no
  axum/tokio server stack) so a client can reuse the external-location module;
  `http` now implies `external`.
- **Added** `external::fetch_external_ipc_bytes`, and
  `resolve_external_location` now merges the *inner* externalized batch's
  metadata in addition to the outer pointer's — peers differ on where they
  stamp per-batch keys like the stream-state token (Rust on the outer pointer,
  Python inside the payload), and the client resolves either layout.
- **Changed** the HTTP unary and stream-init handlers to run inside
  `call_guard`, so a panicking handler surfaces as a structured Arrow
  `EXCEPTION` batch (HTTP 200) matching the stdio/unix loop, rather than a bare
  500. New `http_panic` integration test.
- **Internal** the `CallContext::with_auth_cookies` / `set_sticky` helpers are
  now gated behind the `http` feature (they are http-only; this keeps non-http
  builds warning-clean). The conformance harness (`scripts/conf.py`,
  `test_rust_conformance.py`) gained `--role {server,client}` /
  `--server {rust,python,go}` so the Rust client is conformance-tested against
  all three servers, and CI runs a `{server,rust}` / `{client,rust}` /
  `{client,python}` matrix.

## [0.2.0] — 2026-06-03

First release since the initial `0.1.0` port. Headline: a production-hardening
pass, AEAD-sealed stateless stream tokens, opt-in sticky sessions, application
protocol-version enforcement, and the `__transport_options__` capability
handshake. Byte-for-byte conformant with the Python canonical — 901/901
conformance tests pass across pipe / subprocess / HTTP / unix.

- **Added** `__transport_options__` framework handshake (parallel to
  `__describe__`): a pre-dispatch interception in `RpcServer` that reports
  transport capabilities (currently POSIX shared memory) as
  `vgi_rpc.transport.*` response metadata. Not a registered method, so it stays
  out of `methods` / `__describe__` and does not perturb the protocol hash.
  Mirrors Python `vgi_rpc.transport_options`. New `vgi_rpc::transport_options`
  module and `metadata::TRANSPORT_SHM_KEY`.
- **Added** per-tick input-batch metadata surfaced to producer/exchange
  handlers via `CallContext::tick_metadata` (e.g. dynamic `vgi_pushdown_filters`),
  plus an optional per-producer `ProducerState::batch_limit` HTTP continuation
  cap.
- **Added** launcher worker contract (server side): `vgi_rpc::unix::serve_unix`
  — an AF_UNIX accept loop with optional idle self-termination
  (`max(idle_timeout, 60s)` startup grace, cancel-on-connect /
  re-arm-on-last-disconnect), and a `--idle-timeout SEC` flag on the
  conformance worker's `--unix` mode. A Rust worker can now be spawned, warm-
  reused, and reaped by the Python `vgi_rpc.launcher` unchanged. The launcher
  *tool* itself (client-side orchestration) remains deferred with the Rust
  client.
- **Added** application protocol-version major-compatibility enforcement on
  incoming requests, and `protocol_version` in the `__describe__` response.
- **Fixed** describe-conformance harness: provide the `conformance_describe`
  fixture the upstream `TestDescribeConformance` now requires (describe via a
  real `__describe__` call across the transport matrix).

### AEAD-sealed state tokens (token format v4)

- **Breaking** Stream-state tokens are now sealed with XChaCha20-Poly1305
  (`chacha20poly1305 = "0.10"`) instead of HMAC-SHA256-signed. The
  on-wire layout is `version=0x04 | nonce(24B) | ciphertext+tag`,
  base64-encoded; the `created_at` timestamp moves inside the
  ciphertext and TTL is enforced after authenticity. State contents
  are now confidential to anything between client and server.
- **Breaking** `HttpStateBuilder` rename: `signing_key` → `token_key`,
  `signing_key_hex` → `token_key_hex`, `signing_key_base64` →
  `token_key_base64`, `signing_key_from_env` → `token_key_from_env`.
  Examples, integration tests, and the conformance worker have been
  updated.
- **Changed** principal binding switches from a per-(domain, principal)
  HKDF-derived HMAC subkey to a single master key with the identity
  carried in AEAD associated data. Cross-principal and cross-domain
  replay still fail (now via AAD mismatch); key rotation is simpler
  with a single key to roll.
- **Added** new token-format tests: tampered-ciphertext, tampered-nonce,
  unknown-version, malformed-base64.

### Phase 4: external-location batches + S3 / GCS backends

- **Added** `vgi_rpc::external` module: `ExternalStorage` + `Fetcher`
  traits, `ExternalLocationConfig` (threshold, compression, URL
  validator), `maybe_externalize_batch`, `resolve_external_location`,
  and an `InMemoryStorage` backend for tests/CI. Pointer batches carry
  `vgi_rpc.location`, `vgi_rpc.location.sha256`, and an observability
  `vgi_rpc.location.fetch_ms` claim.
- **Added** server-side transparent externalization: oversized unary
  results and stream output batches are uploaded and replaced with
  zero-row pointer batches when `RpcServer::builder().with_external_location(cfg)`
  is set.
- **Added** `vgi-rpc-s3` crate (`PresignedS3Storage`) + `vgi-rpc-gcs`
  crate (`SignedGcsStorage`) — lean design where users supply a
  pre-signed PUT URL factory so the core avoids pulling the heavy
  aws-sdk-s3 transitive tree. Shared HTTPS `HttpFetcher` lives in
  `vgi-rpc-s3` and is re-exported from `vgi-rpc-gcs`.
- **Added** 5 unit tests + 3 integration tests + 3 backend unit tests.

### Phase 3: observability + HTTP polish

- **Added** `otel::OtelHook` (feature `otel`): per-call `tracing` events
  tagged `vgi_rpc.otel` with method, principal, status, durations,
  statistics; `OtelMetrics` counter/histogram for in-memory scraping;
  W3C `traceparent` extraction helper.
- **Added** `sentry::SentryHook` (feature `sentry`): thin `DispatchHook`
  that emits `tracing::error!` events tagged `vgi_rpc.sentry` on
  handler errors so a `sentry-tracing` layer can capture them.
- **Added** `retry::RetryConfig` with exponential backoff + jitter +
  iterator schedule.
- **Added** HTTP polish: CORS (`cors_origins` / `cors_max_age`) with
  preflight handler, `Accept-Encoding: zstd` response compression via
  an axum middleware, URL prefix mounting, `GET /` landing page,
  `GET /describe` API reference page, `GET /health` liveness probe.
- **Added** 12 new unit tests and a `tests/http_polish.rs` integration
  suite (CORS, prefix, health, describe page, zstd response).

### Phase 2: auth surface

- **Added** core auth framework: `AuthContext`, `AuthRequest`, `Authenticate`
  callback type, `chain_authenticate` / `chain_all`. `AuthContext` is now
  propagated on every `CallContext`, and HTTP requests carry a `cookies`
  map into user handlers.
- **Added** bearer-token helpers:
  `auth::bearer::bearer_authenticate(validator)` and
  `bearer_authenticate_static(HashMap)`.
- **Added** mTLS via `x-forwarded-client-cert` (RFC 8705) with
  `mtls_authenticate_fingerprint`, `mtls_authenticate_subject`, and
  `mtls_authenticate_xfcc`; XFCC parser handles quoted values + multi-hop
  chains.
- **Added** OAuth 2.0 Protected Resource Metadata (RFC 9728):
  `OAuthResourceMetadata`, auto-served at
  `/.well-known/oauth-protected-resource`, with a pre-built
  `WWW-Authenticate` header on 401 responses.
- **Added** JWKS-backed JWT validation behind the `jwt` feature:
  `jwt_authenticate_with` + `JwtConfig` + single-flight JWKS refresh.
- **Added** OAuth2 + PKCE primitives behind `oauth-pkce`:
  `generate_pkce_pair`, HMAC-signed state cookies, return-origin allowlist.
- **Added** `HttpState::builder().authenticate(cb).oauth_resource_metadata(m)`.
- **Added** 4 HTTP integration tests and 11 new unit tests covering auth
  helpers end-to-end.

### Phase 1: production hygiene

- **Added** `__describe__` introspection behind `RpcServer::builder().enable_describe(true)`.
- **Added** `MethodInfo` fluent builder with `.doc()`, `.param_type()`,
  `.param_default()`, `.param_doc()`, `.header_schema()`.
- **Added** `RpcServer::builder()` and `HttpState::builder()` with
  `server_id`, `server_version`, `enable_describe`, `with_hook`,
  `producer_batch_limit`, `token_ttl`, `max_sessions`, `max_body_size`,
  `signing_key` knobs.
- **Added** HTTP session TTL (default 5 min), background reaper, bounded
  session map (default 10k), typed "expired vs unknown" errors.
- **Added** graceful shutdown for HTTP (`axum::serve::with_graceful_shutdown`)
  and Unix listeners (SIGTERM/SIGINT via `ctrlc` / `tokio::signal`).
- **Added** `DispatchHook` trait + `CallStatistics` accumulator; wired
  through pipe/unix unary + stream dispatch and HTTP unary.
- **Added** `AccessLogHook` — JSON-per-call access records matching the
  Python `vgi_rpc.access_log_conformance` validator.
- **Added** live describe conformance test (`TestRustDescribeConformance`)
  that runs the Python `run_describe_conformance` suite against the Rust
  worker over pipe + HTTP.

## 0.1.0 — initial port

- Wire protocol reader/writer with per-batch custom metadata.
- `RpcServer` dispatch over stdio / Unix sockets.
- HTTP server with HMAC-signed stream state tokens.
- Conformance worker + `scripts/conf.py` harness. All 450 Python
  conformance cases pass across pipe / subprocess / http / unix.
