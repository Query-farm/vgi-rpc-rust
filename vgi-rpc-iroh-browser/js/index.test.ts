import assert from "node:assert/strict";
import test from "node:test";

import { IrohNode, type HeaderPair, type WasmIrohNode } from "./index.ts";

test("raw VGI wasm stream is exposed as one WHATWG duplex stream", async () => {
  const writes: number[][] = [];
  const reads = [new Uint8Array([4, 5]), undefined];
  let writeClosed = false;
  const wasm: WasmIrohNode = {
    endpointId: "01".repeat(32),
    async openVgiStream(endpointId) {
      assert.equal(endpointId, "02".repeat(32));
      return {
        async write(chunk) {
          writes.push([...chunk]);
        },
        async read() {
          return reads.shift();
        },
        closeWrite() {
          writeClosed = true;
        },
        abort() {},
      };
    },
    async fetchHttpi() {
      throw new Error("unused");
    },
    async close() {},
  };

  const stream = await new IrohNode(wasm).openVgiStream("02".repeat(32));
  const writer = stream.writable.getWriter();
  await writer.write(new Uint8Array([1, 2, 3]));
  await writer.close();
  const reader = stream.readable.getReader();
  assert.deepEqual(await reader.read(), {
    done: false,
    value: new Uint8Array([4, 5]),
  });
  assert.deepEqual(await reader.read(), { done: true, value: undefined });
  assert.deepEqual(writes, [[1, 2, 3]]);
  assert.equal(writeClosed, true);
});

test("httpi retains duplicate headers and declares raw representation bytes", async () => {
  const responseHeaders: HeaderPair[] = [
    ["set-cookie", "a=1"],
    ["set-cookie", "b=2"],
  ];
  const wasm: WasmIrohNode = {
    endpointId: "01".repeat(32),
    async openVgiStream() {
      throw new Error("unused");
    },
    async fetchHttpi(_id, method, path, headers, body) {
      assert.equal(method, "POST");
      assert.equal(path, "/vgi");
      assert.deepEqual(headers, [["content-type", "application/vnd.apache.arrow.stream"]]);
      assert.deepEqual([...body], [7]);
      const chunks = [new Uint8Array([8, 9]), undefined];
      return {
        status: 201,
        headers: responseHeaders,
        async read() {
          return chunks.shift();
        },
        cancel() {},
      };
    },
    async close() {},
  };

  const response = await new IrohNode(wasm).fetchHttpi(
    "02".repeat(32),
    "POST",
    "/vgi",
    [["content-type", "application/vnd.apache.arrow.stream"]],
    new Uint8Array([7]),
  );
  assert.equal(response.status, 201);
  assert.equal(response.bodyEncoding, "raw");
  assert.deepEqual(response.headers, responseHeaders);
  assert.deepEqual(await new Response(response.body).bytes(), new Uint8Array([8, 9]));
});

test("application resolver is the optional authorization boundary", async () => {
  let resolved = false;
  const wasm: WasmIrohNode = {
    endpointId: "01".repeat(32),
    async openVgiStream(endpointId) {
      resolved = endpointId === "03".repeat(32);
      return {
        async write() {},
        async read() {
          return undefined;
        },
        closeWrite() {},
        abort() {},
      };
    },
    async fetchHttpi() {
      throw new Error("unused");
    },
    async close() {},
  };
  await new IrohNode(wasm, (target) => {
    assert.equal(target, "authorized-worker");
    return "03".repeat(32);
  }).openVgiStream("authorized-worker");
  assert.equal(resolved, true);
});
