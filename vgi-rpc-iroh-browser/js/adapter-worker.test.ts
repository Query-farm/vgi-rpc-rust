import assert from "node:assert/strict";
import test from "node:test";

import { installIrohVgiAdapter } from "./adapter-worker.ts";
import { HttpiTransportError, IrohNode } from "./index.ts";
import type {
  HeaderPair,
  HttpiResponse,
  VgiDuplexStream,
  WasmHttpResponse,
  WasmIrohNode,
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

test("raw output failure aborts a sibling SAB input pump and publishes promptly", async () => {
  const listeners = installTestScope();
  let aborted = 0;
  const node = {
    endpointId: "01".repeat(32),
    async openVgiStream(): Promise<VgiDuplexStream> {
      return {
        readable: new ReadableStream({
          pull() {
            throw new Error("remote reset");
          },
        }),
        writable: new WritableStream(),
        abort() {
          aborted++;
        },
      };
    },
  } as IrohNode;
  const { buffer, words, stride } = makeRegion(1, 1024);
  const stop = installIrohVgiAdapter(Promise.resolve(node));
  const target = `iroh://${"02".repeat(32)}`;
  for (const listener of listeners)
    listener({ data: { type: "vgi-init", target, buffer, offset: 0 } });
  await new Promise((resolve) => setTimeout(resolve, 5));
  const control = HEADER_BYTES >> 2;
  const started = Date.now();
  Atomics.store(words, control, 101);
  await until(() => Atomics.load(words, control + 6) === 101);
  assert.ok(
    Date.now() - started < 500,
    "terminal state should not wait for the sibling pump",
  );
  assert.equal(Atomics.load(words, control + 8), 3);
  assert.ok(aborted >= 1);
  assert.ok(stride > 0);
  stop();
});

test("httpi pre-response failures use a terminal-only head with decodable evidence", async () => {
  const listeners = installTestScope();
  const node = {
    endpointId: "01".repeat(32),
    async fetchHttpi(): Promise<HttpiResponse> {
      throw new HttpiTransportError(
        "connect",
        "unavailable",
        "not_dispatched",
        new Error("offline"),
      );
    },
  } as IrohNode;
  const { buffer, words } = makeRegion(1, 2048);
  const stop = installIrohVgiAdapter(Promise.resolve(node));
  const target = `httpi://${"02".repeat(32)}`;
  for (const listener of listeners)
    listener({ data: { type: "vgi-init", target, buffer, offset: 0 } });
  await new Promise((resolve) => setTimeout(resolve, 5));
  writeClaim(
    buffer,
    words,
    0,
    2048,
    111,
    encodeHttpiRequest("POST", "/vgi", [], new Uint8Array()),
  );
  const control = HEADER_BYTES >> 2;
  await until(() => Atomics.load(words, control + 6) === 111);
  const bytes = new Uint8Array(
    buffer,
    HEADER_BYTES + SLOT_CONTROL_BYTES + 2048,
    Atomics.load(words, control + 4),
  );
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  assert.equal(view.getUint16(6, true), 3);
  assert.equal(view.getUint16(8, true), 0);
  assert.equal(bytes[16], 3);
  assert.deepEqual(Array.from(bytes.subarray(17, 20)), [3, 3, 1]);
  stop();
});

test("claim release and adapter stop cancel pending raw and httpi opens", async () => {
  const listeners = installTestScope();
  let rawCancelled = false;
  let httpCancelled = false;
  const node = {
    endpointId: "01".repeat(32),
    openVgiStream(_target: string, options: { signal?: AbortSignal }) {
      return new Promise<VgiDuplexStream>((_resolve, reject) =>
        options.signal?.addEventListener(
          "abort",
          () => {
            rawCancelled = true;
            reject(options.signal?.reason);
          },
          { once: true },
        ),
      );
    },
    fetchHttpi(
      _target: string,
      _method: string,
      _path: string,
      _headers: HeaderPair[],
      _body: Uint8Array,
      signal?: AbortSignal,
    ) {
      return new Promise<HttpiResponse>((_resolve, reject) =>
        signal?.addEventListener(
          "abort",
          () => {
            httpCancelled = true;
            reject(signal.reason);
          },
          { once: true },
        ),
      );
    },
  } as IrohNode;
  const rawRegion = makeRegion(1, 1024);
  const httpRegion = makeRegion(1, 1024);
  const stop = installIrohVgiAdapter(Promise.resolve(node));
  for (const listener of listeners) {
    listener({
      data: {
        type: "vgi-init",
        target: `iroh://${"02".repeat(32)}`,
        buffer: rawRegion.buffer,
        offset: 0,
      },
    });
    listener({
      data: {
        type: "vgi-register-target",
        requestId: "h",
        target: `httpi://${"03".repeat(32)}`,
        buffer: httpRegion.buffer,
        offset: 0,
      },
    });
  }
  await new Promise((resolve) => setTimeout(resolve, 5));
  Atomics.store(rawRegion.words, HEADER_BYTES >> 2, 121);
  writeClaim(
    httpRegion.buffer,
    httpRegion.words,
    0,
    1024,
    122,
    encodeHttpiRequest("POST", "/vgi", [], new Uint8Array()),
  );
  await new Promise((resolve) => setTimeout(resolve, 10));
  Atomics.store(rawRegion.words, HEADER_BYTES >> 2, 0);
  await until(() => rawCancelled);
  stop();
  await until(() => httpCancelled);
});

test("httpi aggregate admission prevents concurrent buffered claims from multiplying the cap", async () => {
  const listeners = installTestScope();
  let firstStarted = false;
  const node = {
    endpointId: "01".repeat(32),
    fetchHttpi(
      _target: string,
      _method: string,
      _path: string,
      _headers: HeaderPair[],
      _body: Uint8Array,
      signal?: AbortSignal,
    ) {
      firstStarted = true;
      return new Promise<HttpiResponse>((_resolve, reject) =>
        signal?.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        }),
      );
    },
  } as IrohNode;
  const cap = 1024;
  const { buffer, words } = makeRegion(2, cap);
  const stop = installIrohVgiAdapter(Promise.resolve(node), {
    maxHttpiRequestBytes: 8,
    maxHttpiAggregateRequestBytes: 8,
  });
  const target = `httpi://${"02".repeat(32)}`;
  for (const listener of listeners)
    listener({ data: { type: "vgi-init", target, buffer, offset: 0 } });
  await new Promise((resolve) => setTimeout(resolve, 5));
  writeClaim(
    buffer,
    words,
    0,
    cap,
    131,
    encodeHttpiRequest("POST", "/vgi", [], new Uint8Array(6)),
  );
  await until(() => firstStarted);
  writeClaim(
    buffer,
    words,
    1,
    cap,
    132,
    encodeHttpiRequest("POST", "/vgi", [], new Uint8Array(6)),
  );
  const secondControl = (HEADER_BYTES + (SLOT_CONTROL_BYTES + cap * 2)) >> 2;
  await until(() => Atomics.load(words, secondControl + 6) === 132);
  const out = new Uint8Array(
    buffer,
    (secondControl << 2) + SLOT_CONTROL_BYTES + cap,
    Atomics.load(words, secondControl + 4),
  );
  assert.equal(
    new DataView(out.buffer, out.byteOffset, out.byteLength).getUint16(6, true),
    3,
  );
  assert.match(
    new TextDecoder().decode(out),
    /aggregate request-body budget exhausted/,
  );
  stop();
});

test("httpi body budget remains charged until an aborted wasm request actually settles", async (t) => {
  const listeners = installTestScope();
  let resolveFirst!: (response: WasmHttpResponse) => void;
  let fetchCalls = 0;
  let lateCancelled = false;
  const wasm = {
    endpointId: "01".repeat(32),
    async openVgiStream() {
      throw new Error("unused");
    },
    fetchHttpi() {
      fetchCalls++;
      if (fetchCalls === 1) {
        return new Promise<WasmHttpResponse>((resolve) => {
          resolveFirst = resolve;
        });
      }
      return Promise.resolve({
        status: 200,
        headers: [],
        async read() {
          return undefined;
        },
        cancel() {},
      });
    },
    async close() {},
  } as WasmIrohNode;
  const node = new IrohNode(wasm);
  const cap = 1024;
  const { buffer, words } = makeRegion(2, cap);
  const stride = SLOT_CONTROL_BYTES + cap * 2;
  const firstControl = HEADER_BYTES >> 2;
  const secondControl = (HEADER_BYTES + stride) >> 2;
  const stop = installIrohVgiAdapter(Promise.resolve(node), {
    maxHttpiRequestBytes: 8,
    maxHttpiAggregateRequestBytes: 8,
  });
  t.after(stop);
  for (const listener of listeners)
    listener({
      data: {
        type: "vgi-init",
        target: `httpi://${"02".repeat(32)}`,
        buffer,
        offset: 0,
      },
    });
  await new Promise((resolve) => setTimeout(resolve, 5));

  writeClaim(
    buffer,
    words,
    0,
    cap,
    141,
    encodeHttpiRequest("POST", "/vgi", [], new Uint8Array(6)),
  );
  await until(() => fetchCalls === 1 && typeof resolveFirst === "function");

  // Releasing the SAB claim aborts the caller-visible wrapper, but the wasm
  // future still owns the Uint8Array. Its six-byte lease must remain charged.
  Atomics.store(words, firstControl, 0);
  writeClaim(
    buffer,
    words,
    1,
    cap,
    142,
    encodeHttpiRequest("POST", "/vgi", [], new Uint8Array(6)),
  );
  await until(() => Atomics.load(words, secondControl + 6) === 142);
  const rejected = new Uint8Array(
    buffer,
    (secondControl << 2) + SLOT_CONTROL_BYTES + cap,
    Atomics.load(words, secondControl + 4),
  );
  assert.match(
    new TextDecoder().decode(rejected),
    /aggregate request-body budget exhausted/,
  );
  assert.equal(fetchCalls, 1);

  resolveFirst({
    status: 200,
    headers: [],
    async read() {
      return undefined;
    },
    cancel() {
      lateCancelled = true;
    },
  });
  await until(() => lateCancelled);

  // Once the real wasm promise settles, the lease is released and another
  // six-byte request is admitted.
  for (let index = 0; index < SLOT_CONTROL_BYTES / 4; index++)
    Atomics.store(words, secondControl + index, 0);
  writeClaim(
    buffer,
    words,
    1,
    cap,
    143,
    encodeHttpiRequest("POST", "/vgi", [], new Uint8Array(6)),
  );
  await until(() => fetchCalls === 2);
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

function installTestScope(): Set<(event: { data: unknown }) => void> {
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
  return listeners;
}

function makeRegion(
  nSlots: number,
  ringCapacity: number,
): {
  buffer: SharedArrayBuffer;
  words: Int32Array;
  stride: number;
} {
  const stride = SLOT_CONTROL_BYTES + ringCapacity * 2;
  const buffer = new SharedArrayBuffer(HEADER_BYTES + nSlots * stride);
  const words = new Int32Array(buffer);
  words.set([MAGIC, 1, nSlots, ringCapacity, stride, HEADER_BYTES, 1]);
  return { buffer, words, stride };
}

function writeClaim(
  buffer: SharedArrayBuffer,
  words: Int32Array,
  slot: number,
  ringCapacity: number,
  claim: number,
  request: Uint8Array,
): void {
  const stride = SLOT_CONTROL_BYTES + ringCapacity * 2;
  const control = (HEADER_BYTES + slot * stride) >> 2;
  new Uint8Array(buffer).set(request, (control << 2) + SLOT_CONTROL_BYTES);
  Atomics.store(words, control + 1, request.length);
  Atomics.store(words, control + 3, 1);
  Atomics.store(words, control, claim);
  Atomics.notify(words, control + 1);
}

async function until(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
