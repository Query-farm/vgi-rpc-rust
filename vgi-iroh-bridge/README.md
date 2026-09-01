# vgi-iroh-bridge

This is a narrow transport bridge, not a service load balancer.

For `vgi-rpc/arrow-mux/1`, each authenticated Iroh bidirectional stream opens
one TCP or Unix-domain connection to one configured upstream VGI worker. The
bridge writes the canonical VGI Iroh PROXY-v2 identity preamble before copying
bytes in both directions. Stream failure cannot migrate or replay state on a
different worker.

The upstream listener must require PROXY v2, explicitly enable Iroh forwarding,
trust only the bridge's exact immediate address, and choose its own stable
issuer. The bridge forwards the raw cryptographic EndpointId but never forwards
an issuer or authorization decision.

HTTP support is intentionally added only through iroh-http's shared
already-negotiated connection loop. VGI will not carry a forked copy of that
loop because doing so would duplicate its peer identity, header/body bounds,
slowloris, middleware, request tracking, and drain invariants.
