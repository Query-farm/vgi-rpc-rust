import initWasm, {
  createIrohNode as createWasmIrohNode,
} from "demo-iroh-bindings";

import { installIrohVgiAdapter } from "../js/adapter-worker.ts";
import { createIrohNode } from "../js/index.ts";

const scope = self as DedicatedWorkerGlobalScope;

// One endpoint is created for the lifetime of this adapter Worker. Haybarn may
// register several httpi:// or iroh:// SAB regions on it; they all retain this
// same cryptographic client identity and share the transport's connection pool.
const nodePromise = (async () => {
  await initWasm();
  const node = await createIrohNode((options) => createWasmIrohNode(options));
  scope.postMessage({
    type: "demo-iroh-identity",
    endpointId: node.endpointId,
  });
  return node;
})();

installIrohVgiAdapter(nodePromise);

void nodePromise.catch((error: unknown) => {
  scope.postMessage({
    type: "demo-iroh-error",
    error: error instanceof Error ? error.message : String(error),
  });
});
