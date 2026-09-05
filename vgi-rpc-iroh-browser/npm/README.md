# @query-farm/vgi-rpc-iroh-browser

Browser WebAssembly transport for VGI RPC over authenticated Iroh connections.
It supports both `vgi-rpc/arrow-mux/1` byte streams and `iroh-http/2` requests.

```ts
import { createIrohNode } from "@query-farm/vgi-rpc-iroh-browser";

const node = await createIrohNode({
  relayUrls: ["https://relay.example.com"],
});
const stream = await node.openVgiStream("<64-hex-endpoint-id>");
```

Use one node per browser engine so raw VGI and HTTP-over-Iroh calls share the
same cryptographic client identity and connection pools. Browser deployment
requires a secure context; the Haybarn SharedArrayBuffer adapter additionally
requires cross-origin isolation and `@haybarn/haybarn-wasm >= 1.5.5-rc4`. The
wrapper version is independent of the embedded `haybarn-v1.5.5-rc1` engine ABI.

Set `noRelay: true` only for controlled direct-connect environments. It is
mutually exclusive with `relayUrls`.
