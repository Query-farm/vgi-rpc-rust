import { HttpiTransportError } from "./index.ts";
import type {
  HeaderPair,
  HttpiResponse,
  IrohNode,
  VgiDuplexStream,
} from "./index.ts";

const MAGIC = 0x42534756;
const VERSION = 1;
const HEADER_BYTES = 64;
const SLOT_CONTROL_BYTES = 64;

const HDR_MAGIC = 0;
const HDR_VERSION = 1;
const HDR_N_SLOTS = 2;
const HDR_RING_CAP = 3;
const HDR_SLOT_STRIDE = 4;
const HDR_SLOTS_OFF = 5;
const HDR_FEATURES = 6;

const STATE = 0;
const C2W_WRITE = 1;
const C2W_READ = 2;
const C2W_CLOSED = 3;
const W2C_WRITE = 4;
const W2C_READ = 5;
const W2C_CLOSED = 6;
const TERMINAL_CLAIM = 7;
const TERMINAL_CODE = 8;
const TERMINAL_DETAIL = 9;

const FEATURE_TERMINAL_ERROR = 1 << 0;
const ERROR_OPEN = 1;
const ERROR_CLIENT_TO_IROH = 2;
const ERROR_IROH_TO_CLIENT = 3;
const POLL_MS = 10;
const IO_CHUNK_BYTES = 64 * 1024;
const HTTPI_MAGIC = new Uint8Array([0x56, 0x47, 0x49, 0x48]);
const HTTPI_VERSION = 1;
const HTTPI_REQUEST = 1;
const HTTPI_RESPONSE = 2;
const HTTPI_RAW_REPRESENTATION = 1;
const HTTPI_TERMINAL_ONLY = 2;
const BODY_CHUNK = 1;
const BODY_END = 2;
const BODY_TERMINAL = 3;
const MAX_HEADERS = 1024;
const MAX_HEADER_BYTES = 1024 * 1024;
const DEFAULT_MAX_REQUEST_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_AGGREGATE_REQUEST_BYTES = 128 * 1024 * 1024;
const MAX_DETAIL_BYTES = 512;

const STAGE_PARSE = 1;
const STAGE_RESOLVE = 2;
const STAGE_CONNECT = 3;
const STAGE_REQUEST = 4;
const STAGE_RESPONSE_HEAD = 5;
const STAGE_RESPONSE_BODY = 6;
const CATEGORY_INVALID_REQUEST = 1;
const CATEGORY_UNAUTHORIZED_TARGET = 2;
const CATEGORY_UNAVAILABLE = 3;
const CATEGORY_TIMEOUT = 4;
const CATEGORY_CANCELLED = 5;
const CATEGORY_PROTOCOL = 6;
const CATEGORY_TRANSPORT = 7;
const CATEGORY_INTERNAL = 8;
const DISPATCH_NOT_DISPATCHED = 1;
const DISPATCH_DISPATCHED = 2;
const DISPATCH_AMBIGUOUS = 3;

interface RegionMessage {
  type: "vgi-init" | "vgi-register-target";
  requestId?: string;
  target: string;
  buffer: SharedArrayBuffer;
  offset: number;
}

interface UnregisterMessage {
  type: "vgi-unregister-target";
  target: string;
  offset: number;
}

type AdapterMessage = RegionMessage | UnregisterMessage;

interface Region {
  target: string;
  endpointId: string;
  protocol: "raw" | "httpi";
  buffer: SharedArrayBuffer;
  bytes: Uint8Array;
  words: Int32Array;
  base: number;
  nSlots: number;
  ringCap: number;
  stride: number;
  slotsOffset: number;
  running: Map<number, ActiveClaim>;
  stopped: boolean;
}

interface ActiveClaim {
  claim: number;
  controller: AbortController;
}

export interface IrohVgiAdapterOptions {
  maxHttpiRequestBytes?: number;
  maxHttpiAggregateRequestBytes?: number;
}

class RequestBodyBudget {
  used = 0;
  constructor(
    readonly perRequest: number,
    readonly aggregate: number,
  ) {}
  reserve(current: number, additional: number): void {
    if (current + additional > this.perRequest)
      throw new Error("HTTPI request body exceeds per-request limit");
    if (this.used + additional > this.aggregate)
      throw new Error("HTTPI aggregate request-body budget exhausted");
    this.used += additional;
  }
  release(bytes: number): void {
    this.used = Math.max(0, this.used - bytes);
  }
}

type WaitAsyncResult =
  | { async: false; value: string }
  | { async: true; value: Promise<string> };

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForChange(
  words: Int32Array,
  index: number,
  value: number,
): Promise<void> {
  const waitAsync = (
    Atomics as typeof Atomics & {
      waitAsync?: (
        array: Int32Array,
        index: number,
        value: number,
        timeout?: number,
      ) => WaitAsyncResult;
    }
  ).waitAsync;
  if (waitAsync) {
    const result = waitAsync(words, index, value, 250);
    if (result.async) await result.value;
    return;
  }
  await delay(POLL_MS);
}

function slotWord(region: Region, slot: number): number {
  return (region.base + region.slotsOffset + slot * region.stride) >> 2;
}

function claimStillOwned(
  region: Region,
  slot: number,
  claim: number,
  signal?: AbortSignal,
): boolean {
  return (
    !signal?.aborted &&
    !region.stopped &&
    Atomics.load(region.words, slotWord(region, slot) + STATE) === claim
  );
}

function copyRingOut(
  bytes: Uint8Array,
  dataOffset: number,
  ringCapacity: number,
  position: number,
  length: number,
): Uint8Array {
  const output = new Uint8Array(length);
  const start = position % ringCapacity;
  const first = Math.min(length, ringCapacity - start);
  output.set(bytes.subarray(dataOffset + start, dataOffset + start + first));
  if (length > first)
    output.set(bytes.subarray(dataOffset, dataOffset + length - first), first);
  return output;
}

function copyRingIn(
  bytes: Uint8Array,
  dataOffset: number,
  ringCapacity: number,
  position: number,
  source: Uint8Array,
  sourceOffset: number,
  length: number,
): void {
  const start = position % ringCapacity;
  const first = Math.min(length, ringCapacity - start);
  bytes.set(
    source.subarray(sourceOffset, sourceOffset + first),
    dataOffset + start,
  );
  if (length > first) {
    bytes.set(
      source.subarray(sourceOffset + first, sourceOffset + length),
      dataOffset,
    );
  }
}

async function readClientChunk(
  region: Region,
  slot: number,
  claim: number,
  signal?: AbortSignal,
): Promise<Uint8Array | undefined> {
  const control = slotWord(region, slot);
  const dataOffset = (control << 2) + SLOT_CONTROL_BYTES;
  for (;;) {
    if (!claimStillOwned(region, slot, claim, signal)) return undefined;
    const write = Atomics.load(region.words, control + C2W_WRITE);
    const read = Atomics.load(region.words, control + C2W_READ);
    const available = write - read;
    if (available > 0) {
      const length = Math.min(available, IO_CHUNK_BYTES);
      const chunk = copyRingOut(
        region.bytes,
        dataOffset,
        region.ringCap,
        read,
        length,
      );
      Atomics.store(region.words, control + C2W_READ, read + length);
      Atomics.notify(region.words, control + C2W_READ);
      return chunk;
    }
    if (Atomics.load(region.words, control + C2W_CLOSED) !== 0)
      return undefined;
    await waitForChange(region.words, control + C2W_WRITE, write);
  }
}

async function writeWorkerChunk(
  region: Region,
  slot: number,
  claim: number,
  chunk: Uint8Array,
  signal?: AbortSignal,
): Promise<boolean> {
  const control = slotWord(region, slot);
  const dataOffset = (control << 2) + SLOT_CONTROL_BYTES + region.ringCap;
  let offset = 0;
  while (offset < chunk.length) {
    if (!claimStillOwned(region, slot, claim, signal)) return false;
    const write = Atomics.load(region.words, control + W2C_WRITE);
    const read = Atomics.load(region.words, control + W2C_READ);
    const free = region.ringCap - (write - read);
    if (free === 0) {
      await waitForChange(region.words, control + W2C_READ, read);
      continue;
    }
    const length = Math.min(free, chunk.length - offset);
    copyRingIn(
      region.bytes,
      dataOffset,
      region.ringCap,
      write,
      chunk,
      offset,
      length,
    );
    Atomics.store(region.words, control + W2C_WRITE, write + length);
    Atomics.notify(region.words, control + W2C_WRITE);
    offset += length;
  }
  return true;
}

class RingReader {
  // Chunks may be backed by either an ordinary ArrayBuffer (Iroh/Web streams)
  // or the SharedArrayBuffer ring. Keep the backing type honest at this
  // boundary; TypeScript 6 no longer silently treats the two as identical.
  private pending: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  private readonly region: Region;
  private readonly slot: number;
  private readonly claim: number;
  private readonly signal?: AbortSignal;

  constructor(
    region: Region,
    slot: number,
    claim: number,
    signal?: AbortSignal,
  ) {
    this.region = region;
    this.slot = slot;
    this.claim = claim;
    this.signal = signal;
  }

  async exact(length: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(length) || length < 0)
      throw new Error("invalid envelope length");
    const output = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      if (this.pending.length === 0) {
        const chunk = await readClientChunk(
          this.region,
          this.slot,
          this.claim,
          this.signal,
        );
        if (chunk === undefined)
          throw new Error("request envelope ended early");
        this.pending = chunk;
      }
      const take = Math.min(length - offset, this.pending.length);
      output.set(this.pending.subarray(0, take), offset);
      this.pending = this.pending.subarray(take);
      offset += take;
    }
    return output;
  }
}

function u16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function u32(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

function putU16(view: DataView, offset: number, value: number): void {
  view.setUint16(offset, value, true);
}

function putU32(view: DataView, offset: number, value: number): void {
  view.setUint32(offset, value, true);
}

function responseHead(
  status: number,
  headers: HeaderPair[],
  terminalOnly = false,
): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = headers.map(
    ([name, value]) => [encoder.encode(name), encoder.encode(value)] as const,
  );
  const headerBytes = encoded.reduce(
    (sum, [name, value]) => sum + name.length + value.length,
    0,
  );
  if (headers.length > MAX_HEADERS || headerBytes > MAX_HEADER_BYTES) {
    throw new Error("response headers exceed HTTPI envelope limits");
  }
  const bytes = new Uint8Array(
    16 +
      encoded.reduce(
        (sum, [name, value]) => sum + 8 + name.length + value.length,
        0,
      ),
  );
  bytes.set(HTTPI_MAGIC, 0);
  bytes[4] = HTTPI_VERSION;
  bytes[5] = HTTPI_RESPONSE;
  const view = new DataView(bytes.buffer);
  putU16(
    view,
    6,
    HTTPI_RAW_REPRESENTATION | (terminalOnly ? HTTPI_TERMINAL_ONLY : 0),
  );
  putU16(view, 8, status);
  putU16(view, 10, 0);
  putU32(view, 12, headers.length);
  let offset = 16;
  for (const [name, value] of encoded) {
    putU32(view, offset, name.length);
    putU32(view, offset + 4, value.length);
    offset += 8;
    bytes.set(name, offset);
    offset += name.length;
    bytes.set(value, offset);
    offset += value.length;
  }
  return bytes;
}

function frame(
  kind: number,
  payload: Uint8Array<ArrayBufferLike> = new Uint8Array(0),
  stage = 0,
  category = 0,
  certainty = 0,
): Uint8Array {
  const bytes = new Uint8Array(8 + payload.length);
  bytes[0] = kind;
  bytes[1] = stage;
  bytes[2] = category;
  bytes[3] = certainty;
  putU32(new DataView(bytes.buffer), 4, payload.length);
  bytes.set(payload, 8);
  return bytes;
}

function sanitizedDetail(error: unknown): Uint8Array {
  const text = (error instanceof Error ? error.message : String(error)).replace(
    /[\u0000-\u001f\u007f]/g,
    " ",
  );
  const encoded = new TextEncoder().encode(text);
  return encoded.length <= MAX_DETAIL_BYTES
    ? encoded
    : encoded.slice(0, MAX_DETAIL_BYTES);
}

async function terminal(
  region: Region,
  slot: number,
  claim: number,
  stage: number,
  category: number,
  certainty: number,
  error: unknown,
  includeHead: boolean,
  signal?: AbortSignal,
): Promise<void> {
  if (
    includeHead &&
    !(await writeWorkerChunk(
      region,
      slot,
      claim,
      responseHead(0, [], true),
      signal,
    ))
  )
    return;
  await writeWorkerChunk(
    region,
    slot,
    claim,
    frame(BODY_TERMINAL, sanitizedDetail(error), stage, category, certainty),
    signal,
  );
  closeWorkerOutput(region, slot, claim);
}

interface HttpiRequest {
  method: string;
  path: string;
  headers: HeaderPair[];
  body: Uint8Array;
  reservedBytes: number;
}

async function readHttpiRequest(
  reader: RingReader,
  budget: RequestBodyBudget,
): Promise<HttpiRequest> {
  let reservedBytes = 0;
  try {
    const prefix = await reader.exact(20);
    if (
      !HTTPI_MAGIC.every((value, index) => prefix[index] === value) ||
      prefix[4] !== HTTPI_VERSION ||
      prefix[5] !== HTTPI_REQUEST ||
      u16(prefix, 6) !== 0
    ) {
      throw new Error("invalid HTTPI request envelope");
    }
    const methodLength = u16(prefix, 8);
    const pathLength = u32(prefix, 12);
    const headerCount = u32(prefix, 16);
    if (
      methodLength === 0 ||
      methodLength > 16 ||
      pathLength === 0 ||
      pathLength > 16 * 1024 ||
      headerCount > MAX_HEADERS
    ) {
      throw new Error("HTTPI request head exceeds limits");
    }
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const method = decoder.decode(await reader.exact(methodLength));
    const path = decoder.decode(await reader.exact(pathLength));
    if (
      !/^[A-Z]+$/.test(method) ||
      !/^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@-]+(?:\/[A-Za-z0-9._~!$&'()*+,;=:@-]+)*)?$/.test(
        path,
      )
    ) {
      throw new Error("invalid HTTPI method or path");
    }
    const headers: HeaderPair[] = [];
    let headerBytes = 0;
    for (let i = 0; i < headerCount; i++) {
      const lengths = await reader.exact(8);
      const nameLength = u32(lengths, 0);
      const valueLength = u32(lengths, 4);
      headerBytes += nameLength + valueLength;
      if (nameLength === 0 || headerBytes > MAX_HEADER_BYTES)
        throw new Error("HTTPI request headers exceed limits");
      const name = decoder.decode(await reader.exact(nameLength));
      const value = decoder.decode(await reader.exact(valueLength));
      if (
        !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
        /[\u0000-\u0008\u000a-\u001f\u007f]/.test(value)
      ) {
        throw new Error("invalid HTTPI header");
      }
      headers.push([name, value]);
    }
    const chunks: Uint8Array[] = [];
    let bodyBytes = 0;
    for (;;) {
      const head = await reader.exact(8);
      const length = u32(head, 4);
      if (head[0] === BODY_END && length === 0) break;
      if (
        head[0] !== BODY_CHUNK ||
        head[1] !== 0 ||
        head[2] !== 0 ||
        head[3] !== 0 ||
        length > IO_CHUNK_BYTES
      ) {
        throw new Error("invalid HTTPI request body frame");
      }
      budget.reserve(bodyBytes, length);
      reservedBytes += length;
      bodyBytes += length;
      chunks.push(await reader.exact(length));
    }
    const body = new Uint8Array(bodyBytes);
    let bodyOffset = 0;
    for (const chunk of chunks) {
      body.set(chunk, bodyOffset);
      bodyOffset += chunk.length;
    }
    return { method, path, headers, body, reservedBytes };
  } catch (error) {
    budget.release(reservedBytes);
    throw error;
  }
}

function closeWorkerOutput(region: Region, slot: number, claim: number): void {
  if (!claimStillOwned(region, slot, claim)) return;
  const control = slotWord(region, slot);
  Atomics.store(region.words, control + W2C_CLOSED, claim);
  Atomics.notify(region.words, control + W2C_WRITE);
}

function closeWorkerError(
  region: Region,
  slot: number,
  claim: number,
  code: number,
): void {
  if (!claimStillOwned(region, slot, claim)) return;
  const control = slotWord(region, slot);
  if (
    (Atomics.load(region.words, (region.base >> 2) + HDR_FEATURES) &
      FEATURE_TERMINAL_ERROR) !==
    0
  ) {
    Atomics.store(region.words, control + TERMINAL_CODE, code);
    Atomics.store(region.words, control + TERMINAL_DETAIL, 0);
    Atomics.store(region.words, control + TERMINAL_CLAIM, claim);
  }
  Atomics.store(region.words, control + W2C_CLOSED, claim);
  Atomics.notify(region.words, control + W2C_WRITE);
}

async function pumpClientToIroh(
  region: Region,
  slot: number,
  claim: number,
  stream: VgiDuplexStream,
  signal: AbortSignal,
): Promise<void> {
  const writer = stream.writable.getWriter();
  try {
    for (;;) {
      const chunk = await readClientChunk(region, slot, claim, signal);
      if (chunk === undefined) {
        if (signal.aborted)
          throw signal.reason ?? new Error("raw Iroh pump cancelled");
        break;
      }
      if (signal.aborted)
        throw signal.reason ?? new Error("raw Iroh pump cancelled");
      await writer.write(chunk);
    }
    await writer.close();
  } finally {
    writer.releaseLock();
  }
}

async function pumpIrohToClient(
  region: Region,
  slot: number,
  claim: number,
  stream: VgiDuplexStream,
  signal: AbortSignal,
): Promise<void> {
  const reader = stream.readable.getReader();
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      if (
        !(await writeWorkerChunk(region, slot, claim, result.value, signal))
      ) {
        if (signal.aborted)
          throw signal.reason ?? new Error("raw Iroh pump cancelled");
        break;
      }
      if (signal.aborted)
        throw signal.reason ?? new Error("raw Iroh pump cancelled");
    }
  } finally {
    reader.releaseLock();
  }
}

async function serveClaim(
  node: IrohNode,
  region: Region,
  slot: number,
  claim: number,
  signal: AbortSignal,
): Promise<void> {
  let stream: VgiDuplexStream;
  try {
    stream = await node.openVgiStream(region.endpointId, { signal });
  } catch {
    if (!signal.aborted) closeWorkerError(region, slot, claim, ERROR_OPEN);
    return;
  }
  const pumps = new AbortController();
  const cancelPumps = () => {
    pumps.abort(signal.reason ?? new Error("Iroh claim cancelled"));
    stream.abort(signal.reason);
  };
  signal.addEventListener("abort", cancelPumps, { once: true });
  let published = false;
  const fail = (code: number, error: unknown) => {
    if (published) return;
    published = true;
    pumps.abort(error);
    stream.abort(error);
    closeWorkerError(region, slot, claim, code);
  };
  const input = pumpClientToIroh(
    region,
    slot,
    claim,
    stream,
    pumps.signal,
  ).catch((error) => {
    fail(ERROR_CLIENT_TO_IROH, error);
    throw error;
  });
  const output = pumpIrohToClient(
    region,
    slot,
    claim,
    stream,
    pumps.signal,
  ).catch((error) => {
    fail(ERROR_IROH_TO_CLIENT, error);
    throw error;
  });
  const [inputResult, outputResult] = await Promise.allSettled([input, output]);
  signal.removeEventListener("abort", cancelPumps);
  if (
    !published &&
    inputResult.status === "fulfilled" &&
    outputResult.status === "fulfilled" &&
    !signal.aborted
  ) {
    closeWorkerOutput(region, slot, claim);
  }
}

async function serveHttpiClaim(
  node: IrohNode,
  region: Region,
  slot: number,
  claim: number,
  signal: AbortSignal,
  budget: RequestBodyBudget,
): Promise<void> {
  let request: HttpiRequest;
  try {
    request = await readHttpiRequest(
      new RingReader(region, slot, claim, signal),
      budget,
    );
  } catch (error) {
    if (signal.aborted) return;
    await terminal(
      region,
      slot,
      claim,
      STAGE_PARSE,
      CATEGORY_INVALID_REQUEST,
      DISPATCH_NOT_DISPATCHED,
      error,
      true,
      signal,
    );
    return;
  }

  let response: HttpiResponse;
  try {
    response = await node.fetchHttpi(
      region.endpointId,
      request.method,
      request.path,
      request.headers,
      request.body,
      signal,
    );
  } catch (error) {
    if (signal.aborted) return;
    const structured = error instanceof HttpiTransportError ? error : undefined;
    const stages = {
      parse: STAGE_PARSE,
      resolve: STAGE_RESOLVE,
      connect: STAGE_CONNECT,
      request: STAGE_REQUEST,
      response_head: STAGE_RESPONSE_HEAD,
      response_body: STAGE_RESPONSE_BODY,
    };
    const categories = {
      invalid_request: CATEGORY_INVALID_REQUEST,
      unauthorized_target: CATEGORY_UNAUTHORIZED_TARGET,
      unavailable: CATEGORY_UNAVAILABLE,
      timeout: CATEGORY_TIMEOUT,
      cancelled: CATEGORY_CANCELLED,
      protocol: CATEGORY_PROTOCOL,
      transport: CATEGORY_TRANSPORT,
      internal: CATEGORY_INTERNAL,
    };
    const certainties = {
      not_dispatched: DISPATCH_NOT_DISPATCHED,
      dispatched: DISPATCH_DISPATCHED,
      ambiguous: DISPATCH_AMBIGUOUS,
    };
    const stage = structured ? stages[structured.stage] : STAGE_REQUEST;
    const category = structured
      ? categories[structured.category]
      : CATEGORY_TRANSPORT;
    const certainty = structured
      ? certainties[structured.dispatchCertainty]
      : DISPATCH_AMBIGUOUS;
    await terminal(
      region,
      slot,
      claim,
      stage,
      category,
      certainty,
      error,
      true,
      signal,
    );
    return;
  } finally {
    budget.release(request.reservedBytes);
    request.body = new Uint8Array();
  }

  try {
    if (response.bodyEncoding !== "raw")
      throw new Error("HTTPI response is not raw representation bytes");
    if (
      !Number.isInteger(response.status) ||
      response.status < 100 ||
      response.status > 999
    ) {
      throw new Error("invalid HTTPI response status");
    }
    if (
      !(await writeWorkerChunk(
        region,
        slot,
        claim,
        responseHead(response.status, response.headers),
        signal,
      ))
    ) {
      await response.body.cancel(
        "VGI HTTPI SAB slot released before response head delivery",
      );
      return;
    }
  } catch (error) {
    await response.body.cancel("VGI HTTPI rejected response head");
    await terminal(
      region,
      slot,
      claim,
      STAGE_RESPONSE_HEAD,
      CATEGORY_PROTOCOL,
      DISPATCH_DISPATCHED,
      error,
      true,
      signal,
    );
    return;
  }

  const reader = response.body.getReader();
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      if (result.value.length > IO_CHUNK_BYTES) {
        for (
          let offset = 0;
          offset < result.value.length;
          offset += IO_CHUNK_BYTES
        ) {
          if (
            !(await writeWorkerChunk(
              region,
              slot,
              claim,
              frame(
                BODY_CHUNK,
                result.value.subarray(offset, offset + IO_CHUNK_BYTES),
              ),
              signal,
            ))
          ) {
            await reader.cancel(
              "VGI HTTPI SAB slot released during response body",
            );
            return;
          }
        }
      } else if (
        !(await writeWorkerChunk(
          region,
          slot,
          claim,
          frame(BODY_CHUNK, result.value),
          signal,
        ))
      ) {
        await reader.cancel("VGI HTTPI SAB slot released during response body");
        return;
      }
    }
    await writeWorkerChunk(region, slot, claim, frame(BODY_END), signal);
    closeWorkerOutput(region, slot, claim);
  } catch (error) {
    await terminal(
      region,
      slot,
      claim,
      STAGE_RESPONSE_BODY,
      CATEGORY_TRANSPORT,
      DISPATCH_DISPATCHED,
      error,
      false,
      signal,
    );
  } finally {
    reader.releaseLock();
  }
}

function parseRegion(message: RegionMessage): Region {
  const rawMatch = /^iroh:\/\/([0-9a-f]{64})$/.exec(message.target);
  const httpiMatch =
    /^httpi:\/\/([0-9a-f]{64})(?:\/(?:[A-Za-z0-9._~!$&'()*+,;=:@-]+(?:\/[A-Za-z0-9._~!$&'()*+,;=:@-]+)*))?$/.exec(
      message.target,
    );
  const match = rawMatch ?? httpiMatch;
  if (!match)
    throw new Error(
      "adapter target must be a canonical iroh:// or httpi:// EndpointId target",
    );
  if (!(message.buffer instanceof SharedArrayBuffer))
    throw new Error("adapter buffer must be shared");
  if (
    !Number.isSafeInteger(message.offset) ||
    message.offset < 0 ||
    (message.offset & 3) !== 0
  ) {
    throw new Error(
      "adapter region offset must be a non-negative aligned integer",
    );
  }
  const words = new Int32Array(message.buffer);
  const header = message.offset >> 2;
  const nSlots = Atomics.load(words, header + HDR_N_SLOTS);
  const ringCap = Atomics.load(words, header + HDR_RING_CAP);
  const stride = Atomics.load(words, header + HDR_SLOT_STRIDE);
  const slotsOffset = Atomics.load(words, header + HDR_SLOTS_OFF);
  if (
    Atomics.load(words, header + HDR_MAGIC) !== MAGIC ||
    Atomics.load(words, header + HDR_VERSION) !== VERSION ||
    nSlots <= 0 ||
    nSlots > 1024 ||
    ringCap <= 0 ||
    stride < SLOT_CONTROL_BYTES + ringCap * 2 ||
    slotsOffset < HEADER_BYTES ||
    message.offset + slotsOffset + nSlots * stride > message.buffer.byteLength
  ) {
    throw new Error("invalid VGI SAB region header");
  }
  return {
    target: message.target,
    endpointId: match[1],
    protocol: rawMatch ? "raw" : "httpi",
    buffer: message.buffer,
    bytes: new Uint8Array(message.buffer),
    words,
    base: message.offset,
    nSlots,
    ringCap,
    stride,
    slotsOffset,
    running: new Map(),
    stopped: false,
  };
}

/**
 * Install the complete SAB-to-Iroh mux pump in an application-owned Worker.
 * Returns a local teardown hook for tests or an application-controlled Worker
 * shutdown sequence; it does not close the application-owned Iroh node.
 */
export function installIrohVgiAdapter(
  nodePromise: Promise<IrohNode>,
  options: IrohVgiAdapterOptions = {},
): () => void {
  const regions = new Map<string, Region>();
  let node: IrohNode | undefined;
  let polling = false;
  let installed = true;
  const perRequest = options.maxHttpiRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
  const aggregate =
    options.maxHttpiAggregateRequestBytes ??
    DEFAULT_MAX_AGGREGATE_REQUEST_BYTES;
  if (
    !Number.isSafeInteger(perRequest) ||
    perRequest <= 0 ||
    !Number.isSafeInteger(aggregate) ||
    aggregate < perRequest
  ) {
    throw new RangeError(
      "HTTPI request limits must be positive safe integers and aggregate >= per-request",
    );
  }
  const bodyBudget = new RequestBodyBudget(perRequest, aggregate);
  const cancelActive = (region: Region, reason: unknown) => {
    region.stopped = true;
    for (const [slot, active] of region.running) {
      active.controller.abort(reason);
      const control = slotWord(region, slot);
      Atomics.notify(region.words, control + C2W_WRITE);
      Atomics.notify(region.words, control + W2C_READ);
    }
    region.running.clear();
  };

  const poll = async (): Promise<void> => {
    if (polling || !node) return;
    polling = true;
    try {
      while (installed) {
        let active = false;
        for (const region of regions.values()) {
          if (region.stopped) continue;
          for (let slot = 0; slot < region.nSlots; slot++) {
            const claim = Atomics.load(
              region.words,
              slotWord(region, slot) + STATE,
            );
            const lastClaim = region.running.get(slot);
            if (claim === 0) {
              if (lastClaim !== undefined) {
                lastClaim.controller.abort(new Error("VGI SAB claim released"));
                const control = slotWord(region, slot);
                Atomics.notify(region.words, control + C2W_WRITE);
                Atomics.notify(region.words, control + W2C_READ);
                region.running.delete(slot);
              }
              continue;
            }
            active = true;
            if (!lastClaim || lastClaim.claim !== claim) {
              lastClaim?.controller.abort(new Error("VGI SAB claim replaced"));
              const controller = new AbortController();
              region.running.set(slot, { claim, controller });
              // Retain the completed claim marker until STATE changes. A
              // failed open publishes one terminal error and must not redial
              // the same claim in a tight loop before the client releases it.
              void (region.protocol === "httpi"
                ? serveHttpiClaim(
                    node,
                    region,
                    slot,
                    claim,
                    controller.signal,
                    bodyBudget,
                  )
                : serveClaim(node, region, slot, claim, controller.signal));
            }
          }
        }
        await delay(active ? 1 : POLL_MS);
      }
    } finally {
      polling = false;
    }
  };

  const onMessage = (event: MessageEvent<AdapterMessage>): void => {
    const message = event.data;
    if (!message || typeof message !== "object") return;
    if (message.type === "vgi-unregister-target") {
      const region = regions.get(message.target);
      if (region && region.base === message.offset) {
        cancelActive(region, new Error("VGI target unregistered"));
        regions.delete(message.target);
      }
      return;
    }
    if (message.type !== "vgi-init" && message.type !== "vgi-register-target")
      return;

    void nodePromise.then(
      (resolvedNode) => {
        node = resolvedNode;
        const region = parseRegion(message);
        const old = regions.get(region.target);
        if (old) cancelActive(old, new Error("VGI target region replaced"));
        regions.set(region.target, region);
        void poll();
        if (message.type === "vgi-init") {
          self.postMessage({ type: "vgi-ready", endpointId: node.endpointId });
        } else {
          self.postMessage({
            type: "vgi-target-ready",
            requestId: message.requestId,
          });
        }
      },
      (error) => {
        const detail = error instanceof Error ? error.message : String(error);
        if (message.type === "vgi-init")
          self.postMessage({ type: "vgi-error", error: detail });
        else
          self.postMessage({
            type: "vgi-target-error",
            requestId: message.requestId,
            error: detail,
          });
      },
    );
  };
  self.addEventListener("message", onMessage as EventListener);
  return () => {
    installed = false;
    for (const region of regions.values())
      cancelActive(region, new Error("Iroh adapter stopped"));
    regions.clear();
    self.removeEventListener("message", onMessage as EventListener);
  };
}
