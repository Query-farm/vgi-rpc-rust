# HTTP response budgets

VGI HTTP clients send `VGI-Accept-Max-Response-Bytes` on every request. Its
value uses the strict grammar `[1-9][0-9]*` and cannot exceed `2^53-1`. Servers
that honor it advertise `VGI-Accept-Max-Response-Bytes-Support: true` on normal
and OPTIONS responses. An absent request header preserves legacy behavior.

The server's hard per-request `response_limit_bytes` is the minimum of every
configured application `max_response_bytes`, deployment
`hosting_max_response_bytes`, and client accepted maximum. The independent
`preferred_response_bytes` is advisory and is clamped to that hard limit. Both
values are snapshots on `CallContext`; producer and exchange implementations
can also read them from `OutputCollector`.

Unary, stream-init, producer-continuation, and exchange bodies all fail with a
structured VGI exception if their encoded response exceeds the hard limit. No
continuation cursor is returned with that exception. When external storage is
configured, the HTTP transport may externalize a batch below the usual
threshold to rescue an otherwise oversized inline response; the independent
externalized-response cap still applies before upload.

The native Rust client defaults `accepted_max_response_bytes` to 256 MiB and
enforces the same value locally before and after content decoding. The browser
Iroh/HTTPI transport defaults to 64 MiB, injects exactly one request header,
and stops the streamed body once that limit is crossed. Applications may lower
these defaults. A browser-supplied larger value is clamped to 64 MiB.

Request limits use the same application/deployment split:
`max_request_bytes` and `hosting_max_request_bytes` are intersected with the
transport's raw-body safety limit.
