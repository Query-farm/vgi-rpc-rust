import assert from "node:assert/strict";
import test from "node:test";

import { installIrohVgiAdapter } from "./adapter-worker.ts";
import type {
  HeaderPair,
  HttpiResponse,
  IrohNode,
  VgiDuplexStream,
} from "./index.ts";

const MAGIC = 0x42534756;
const HEADER_BYTES = 64;
const SLOT_CONTROL_BYTES = 64;

test("adapter pumps one claimed SAB slot over one Iroh mux stream", async () => {
  const listeners = new Set<(event: { data: unknown }) => void>();
  const posted: unknown[] = [];
  const workerScope = {
    addEventListener(
      _type: string,
      listener: (event: { data: unknown }) => void,
    ) {
      listeners.add(listener);
    },
    removeEventListener(
      _type: string,
      listener: (event: { data: unknown }) => void,
    ) {
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
  assert.deepEqual(posted[0], {
    type: "vgi-ready",
    endpointId: "01".repeat(32),
  });

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

test("httpi adapter preserves duplicate headers and streams framed bodies through one SAB region", async () => {
  const listeners = new Set<(event: { data: unknown }) => void>();
  const posted: unknown[] = [];
  Object.assign(globalThis, {
    self: {
      addEventListener(
        _type: string,
        listener: (event: { data: unknown }) => void,
      ) {
        listeners.add(listener);
      },
      removeEventListener(
        _type: string,
        listener: (event: { data: unknown }) => void,
      ) {
        listeners.delete(listener);
      },
      postMessage(message: unknown) {
        posted.push(message);
      },
    },
  });

  const calls: Array<{
    target: string;
    method: string;
    path: string;
    headers: HeaderPair[];
    body: Uint8Array;
  }> = [];
  const node = {
    endpointId: "01".repeat(32),
    async fetchHttpi(
      target: string,
      method: string,
      path: string,
      headers: HeaderPair[],
      body: Uint8Array,
    ): Promise<HttpiResponse> {
      calls.push({ target, method, path, headers, body });
      return {
        status: 200,
        headers: [
          ["Set-Cookie", "a=1; Secure"],
          ["Set-Cookie", "b=2; Secure"],
        ],
        bodyEncoding: "raw",
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("pong-"));
            controller.enqueue(new TextEncoder().encode("body"));
            controller.close();
          },
        }),
      };
    },
  } as IrohNode;

  const ringCapacity = 8192;
  const stride = SLOT_CONTROL_BYTES + ringCapacity * 2;
  const buffer = new SharedArrayBuffer(HEADER_BYTES + stride);
  const words = new Int32Array(buffer);
  words.set([MAGIC, 1, 1, ringCapacity, stride, HEADER_BYTES, 1]);
  const stop = installIrohVgiAdapter(Promise.resolve(node));
  const endpoint = "02".repeat(32);
  const target = `httpi://${endpoint}`;
  for (const listener of listeners)
    listener({ data: { type: "vgi-init", target, buffer, offset: 0 } });
  await until(() => posted.length === 1);

  const request = encodeHttpiRequest(
    "POST",
    "/vgi/catalog_attach",
    [
      ["X-Test", "one"],
      ["X-Test", "two"],
    ],
    new TextEncoder().encode("ping-body"),
  );
  const control = HEADER_BYTES >> 2;
  const claim = 73;
  new Uint8Array(buffer).set(request, HEADER_BYTES + SLOT_CONTROL_BYTES);
  Atomics.store(words, control + 1, request.length);
  Atomics.store(words, control + 3, 1);
  Atomics.store(words, control, claim);
  Atomics.notify(words, control + 1);

  await until(() => Atomics.load(words, control + 6) === claim);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].target, endpoint);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].path, "/vgi/catalog_attach");
  assert.deepEqual(calls[0].headers, [
    ["X-Test", "one"],
    ["X-Test", "two"],
  ]);
  assert.equal(new TextDecoder().decode(calls[0].body), "ping-body");

  const outputLength = Atomics.load(words, control + 4);
  const output = new Uint8Array(
    buffer,
    HEADER_BYTES + SLOT_CONTROL_BYTES + ringCapacity,
    outputLength,
  ).slice();
  const decoded = decodeHttpiResponse(output);
  assert.equal(decoded.status, 200);
  assert.equal(decoded.raw, true);
  assert.deepEqual(decoded.headers, [
    ["Set-Cookie", "a=1; Secure"],
    ["Set-Cookie", "b=2; Secure"],
  ]);
  assert.equal(new TextDecoder().decode(decoded.body), "pong-body");
  stop();
});

test("httpi adapter cancels an orphaned response stream when its SAB claim is released", async () => {
  const listeners = new Set<(event: { data: unknown }) => void>();
  Object.assign(globalThis, {
    self: {
      addEventListener(
        _type: string,
        listener: (event: { data: unknown }) => void,
      ) {
        listeners.add(listener);
      },
      removeEventListener(
        _type: string,
        listener: (event: { data: unknown }) => void,
      ) {
        listeners.delete(listener);
      },
      postMessage() {},
    },
  });
  let cancelled = false;
  const node = {
    endpointId: "01".repeat(32),
    async fetchHttpi(): Promise<HttpiResponse> {
      return {
        status: 200,
        headers: [],
        bodyEncoding: "raw",
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(2048));
          },
          cancel() {
            cancelled = true;
          },
        }),
      };
    },
  } as IrohNode;
  const ringCapacity = 512;
  const stride = SLOT_CONTROL_BYTES + ringCapacity * 2;
  const buffer = new SharedArrayBuffer(HEADER_BYTES + stride);
  const words = new Int32Array(buffer);
  words.set([MAGIC, 1, 1, ringCapacity, stride, HEADER_BYTES, 1]);
  const stop = installIrohVgiAdapter(Promise.resolve(node));
  const target = `httpi://${"02".repeat(32)}`;
  for (const listener of listeners)
    listener({ data: { type: "vgi-init", target, buffer, offset: 0 } });
  await new Promise((resolve) => setTimeout(resolve, 10));
  const request = encodeHttpiRequest("POST", "/vgi", [], new Uint8Array());
  const control = HEADER_BYTES >> 2;
  new Uint8Array(buffer).set(request, HEADER_BYTES + SLOT_CONTROL_BYTES);
  Atomics.store(words, control + 1, request.length);
  Atomics.store(words, control + 3, 1);
  Atomics.store(words, control, 91);
  Atomics.notify(words, control + 1);
  await until(() => Atomics.load(words, control + 4) === ringCapacity);
  Atomics.store(words, control, 0);
  Atomics.notify(words, control + 5);
  await until(() => cancelled);
  stop();
});

function encodeHttpiRequest(
  method: string,
  path: string,
  headers: HeaderPair[],
  body: Uint8Array,
): Uint8Array {
  const encoder = new TextEncoder();
  const methodBytes = encoder.encode(method);
  const pathBytes = encoder.encode(path);
  const fieldBytes = headers.map(
    ([name, value]) => [encoder.encode(name), encoder.encode(value)] as const,
  );
  const size =
    20 +
    methodBytes.length +
    pathBytes.length +
    fieldBytes.reduce(
      (sum, [name, value]) => sum + 8 + name.length + value.length,
      0,
    ) +
    8 +
    body.length +
    8;
  const output = new Uint8Array(size);
  output.set([0x56, 0x47, 0x49, 0x48, 1, 1, 0, 0]);
  const view = new DataView(output.buffer);
  view.setUint16(8, methodBytes.length, true);
  view.setUint32(12, pathBytes.length, true);
  view.setUint32(16, headers.length, true);
  let offset = 20;
  output.set(methodBytes, offset);
  offset += methodBytes.length;
  output.set(pathBytes, offset);
  offset += pathBytes.length;
  for (const [name, value] of fieldBytes) {
    view.setUint32(offset, name.length, true);
    view.setUint32(offset + 4, value.length, true);
    offset += 8;
    output.set(name, offset);
    offset += name.length;
    output.set(value, offset);
    offset += value.length;
  }
  output[offset] = 1;
  view.setUint32(offset + 4, body.length, true);
  offset += 8;
  output.set(body, offset);
  offset += body.length;
  output[offset] = 2;
  return output;
}

function decodeHttpiResponse(bytes: Uint8Array): {
  status: number;
  raw: boolean;
  headers: HeaderPair[];
  body: Uint8Array;
} {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  assert.deepEqual(
    Array.from(bytes.subarray(0, 6)),
    [0x56, 0x47, 0x49, 0x48, 1, 2],
  );
  const status = view.getUint16(8, true);
  const headerCount = view.getUint32(12, true);
  const decoder = new TextDecoder();
  const headers: HeaderPair[] = [];
  let offset = 16;
  for (let i = 0; i < headerCount; i++) {
    const nameLength = view.getUint32(offset, true);
    const valueLength = view.getUint32(offset + 4, true);
    offset += 8;
    const name = decoder.decode(bytes.subarray(offset, offset + nameLength));
    offset += nameLength;
    const value = decoder.decode(bytes.subarray(offset, offset + valueLength));
    offset += valueLength;
    headers.push([name, value]);
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (bytes[offset] === 1) {
    const length = view.getUint32(offset + 4, true);
    offset += 8;
    const chunk = bytes.slice(offset, offset + length);
    chunks.push(chunk);
    total += chunk.length;
    offset += length;
  }
  assert.equal(bytes[offset], 2);
  const body = new Uint8Array(total);
  let bodyOffset = 0;
  for (const chunk of chunks) {
    body.set(chunk, bodyOffset);
    bodyOffset += chunk.length;
  }
  return { status, raw: view.getUint16(6, true) === 1, headers, body };
}

async function until(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
