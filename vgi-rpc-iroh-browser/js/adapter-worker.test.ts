import assert from "node:assert/strict";
import test from "node:test";

import { installIrohVgiAdapter } from "./adapter-worker.ts";
import type { IrohNode, VgiDuplexStream } from "./index.ts";

const MAGIC = 0x42534756;
const HEADER_BYTES = 64;
const SLOT_CONTROL_BYTES = 64;

test("adapter pumps one claimed SAB slot over one Iroh mux stream", async () => {
  const listeners = new Set<(event: { data: unknown }) => void>();
  const posted: unknown[] = [];
  const workerScope = {
    addEventListener(_type: string, listener: (event: { data: unknown }) => void) {
      listeners.add(listener);
    },
    removeEventListener(_type: string, listener: (event: { data: unknown }) => void) {
      listeners.delete(listener);
    },
    postMessage(message: unknown) {
      posted.push(message);
    },
  };
  Object.assign(globalThis, { self: workerScope });

  const opened: string[] = [];
  const node = {
    endpointId: "01".repeat(32),
    async openVgiStream(endpointId: string): Promise<VgiDuplexStream> {
      opened.push(endpointId);
      let readableController!: ReadableStreamDefaultController<Uint8Array>;
      return {
        readable: new ReadableStream<Uint8Array>({
          start(controller) {
            readableController = controller;
          },
        }),
        writable: new WritableStream<Uint8Array>({
          write(chunk) {
            readableController.enqueue(chunk.slice());
          },
          close() {
            readableController.close();
          },
        }),
        abort(reason) {
          readableController.error(reason);
        },
      };
    },
  } as IrohNode;

  const ringCapacity = 1024;
  const stride = SLOT_CONTROL_BYTES + ringCapacity * 2;
  const buffer = new SharedArrayBuffer(HEADER_BYTES + stride);
  const words = new Int32Array(buffer);
  words[0] = MAGIC;
  words[1] = 1;
  words[2] = 1;
  words[3] = ringCapacity;
  words[4] = stride;
  words[5] = HEADER_BYTES;
  words[6] = 1;

  const stop = installIrohVgiAdapter(Promise.resolve(node));
  const target = `iroh://${"02".repeat(32)}`;
  for (const listener of listeners) {
    listener({ data: { type: "vgi-init", target, buffer, offset: 0 } });
  }
  await until(() => posted.length === 1);
  assert.deepEqual(posted[0], { type: "vgi-ready", endpointId: "01".repeat(32) });

  const control = HEADER_BYTES >> 2;
  const claim = 42;
  Atomics.store(words, control, claim);
  const input = new TextEncoder().encode("ping");
  new Uint8Array(buffer).set(input, HEADER_BYTES + SLOT_CONTROL_BYTES);
  Atomics.store(words, control + 1, input.length);
  Atomics.store(words, control + 3, 1);
  Atomics.notify(words, control + 1);

  await until(() => Atomics.load(words, control + 6) === claim);
  const outputLength = Atomics.load(words, control + 4);
  const output = new Uint8Array(
    buffer,
    HEADER_BYTES + SLOT_CONTROL_BYTES + ringCapacity,
    outputLength,
  );
  assert.equal(new TextDecoder().decode(output), "ping");
  assert.deepEqual(opened, ["02".repeat(32)]);
  assert.equal(Atomics.load(words, control + 7), 0);

  stop();
  await new Promise((resolve) => setTimeout(resolve, 20));
});

async function until(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
