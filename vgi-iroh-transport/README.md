# vgi-iroh-transport

Arrow-free native client transport for VGI over Iroh. It owns an authenticated
Iroh endpoint, pools connections by remote endpoint ID and ALPN, opens
`vgi-rpc/arrow-mux/1` byte streams, and performs streaming HTTP responses over
`iroh-http/2`.

This crate is the native transport layer. Arrow framing remains in VGI clients,
and the browser continues to use `vgi-rpc-iroh-browser`.
