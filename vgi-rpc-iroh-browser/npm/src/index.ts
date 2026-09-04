import initWasm, {
  createIrohNode as createWasmIrohNode,
} from "./wasm/vgi_rpc_iroh_browser.js";

import {
  createIrohNode as createWrappedIrohNode,
  type CreateIrohOptions,
} from "./transport.js";

export * from "./transport.js";

let initialization: Promise<unknown> | undefined;

/** Initialize the packaged WebAssembly module. Calling this more than once is safe. */
export function initializeIrohWasm(): Promise<unknown> {
  if (!initialization) initialization = initWasm();
  return initialization;
}

/** Create a browser Iroh endpoint backed by the packaged WebAssembly module. */
export async function createIrohNode(options: CreateIrohOptions = {}) {
  await initializeIrohWasm();
  return createWrappedIrohNode(
    (transportOptions) => createWasmIrohNode(transportOptions),
    options,
  );
}
