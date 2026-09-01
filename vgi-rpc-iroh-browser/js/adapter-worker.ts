import type { IrohNode, VgiDuplexStream } from "./index.ts";

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
  buffer: SharedArrayBuffer;
  bytes: Uint8Array;
  words: Int32Array;
  base: number;
  nSlots: number;
  ringCap: number;
  stride: number;
  slotsOffset: number;
  running: Map<number, number>;
  stopped: boolean;
}

type WaitAsyncResult = { async: false; value: string } | { async: true; value: Promise<string> };

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForChange(words: Int32Array, index: number, value: number): Promise<void> {
  const waitAsync = (
    Atomics as typeof Atomics & {
      waitAsync?: (array: Int32Array, index: number, value: number, timeout?: number) => WaitAsyncResult;
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

function claimStillOwned(region: Region, slot: number, claim: number): boolean {
  return !region.stopped && Atomics.load(region.words, slotWord(region, slot) + STATE) === claim;
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
  if (length > first) output.set(bytes.subarray(dataOffset, dataOffset + length - first), first);
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
  bytes.set(source.subarray(sourceOffset, sourceOffset + first), dataOffset + start);
  if (length > first) {
    bytes.set(source.subarray(sourceOffset + first, sourceOffset + length), dataOffset);
  }
}

async function readClientChunk(region: Region, slot: number, claim: number): Promise<Uint8Array | undefined> {
  const control = slotWord(region, slot);
  const dataOffset = (control << 2) + SLOT_CONTROL_BYTES;
  for (;;) {
    if (!claimStillOwned(region, slot, claim)) return undefined;
    const write = Atomics.load(region.words, control + C2W_WRITE);
    const read = Atomics.load(region.words, control + C2W_READ);
    const available = write - read;
    if (available > 0) {
      const length = Math.min(available, IO_CHUNK_BYTES);
      const chunk = copyRingOut(region.bytes, dataOffset, region.ringCap, read, length);
      Atomics.store(region.words, control + C2W_READ, read + length);
      Atomics.notify(region.words, control + C2W_READ);
      return chunk;
    }
    if (Atomics.load(region.words, control + C2W_CLOSED) !== 0) return undefined;
    await waitForChange(region.words, control + C2W_WRITE, write);
  }
}

async function writeWorkerChunk(
  region: Region,
  slot: number,
  claim: number,
  chunk: Uint8Array,
): Promise<boolean> {
  const control = slotWord(region, slot);
  const dataOffset = (control << 2) + SLOT_CONTROL_BYTES + region.ringCap;
  let offset = 0;
  while (offset < chunk.length) {
    if (!claimStillOwned(region, slot, claim)) return false;
    const write = Atomics.load(region.words, control + W2C_WRITE);
    const read = Atomics.load(region.words, control + W2C_READ);
    const free = region.ringCap - (write - read);
    if (free === 0) {
      await waitForChange(region.words, control + W2C_READ, read);
      continue;
    }
    const length = Math.min(free, chunk.length - offset);
    copyRingIn(region.bytes, dataOffset, region.ringCap, write, chunk, offset, length);
    Atomics.store(region.words, control + W2C_WRITE, write + length);
    Atomics.notify(region.words, control + W2C_WRITE);
    offset += length;
  }
  return true;
}

function closeWorkerOutput(region: Region, slot: number, claim: number): void {
  if (!claimStillOwned(region, slot, claim)) return;
  const control = slotWord(region, slot);
  Atomics.store(region.words, control + W2C_CLOSED, claim);
  Atomics.notify(region.words, control + W2C_WRITE);
}

function closeWorkerError(region: Region, slot: number, claim: number, code: number): void {
  if (!claimStillOwned(region, slot, claim)) return;
  const control = slotWord(region, slot);
  if ((Atomics.load(region.words, (region.base >> 2) + HDR_FEATURES) & FEATURE_TERMINAL_ERROR) !== 0) {
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
): Promise<void> {
  const writer = stream.writable.getWriter();
  try {
    for (;;) {
      const chunk = await readClientChunk(region, slot, claim);
      if (chunk === undefined) break;
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
): Promise<void> {
  const reader = stream.readable.getReader();
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      if (!(await writeWorkerChunk(region, slot, claim, result.value))) break;
    }
  } finally {
    reader.releaseLock();
  }
}

async function serveClaim(node: IrohNode, region: Region, slot: number, claim: number): Promise<void> {
  let stream: VgiDuplexStream;
  try {
    stream = await node.openVgiStream(region.endpointId);
  } catch {
    closeWorkerError(region, slot, claim, ERROR_OPEN);
    return;
  }

  const input = pumpClientToIroh(region, slot, claim, stream);
  const output = pumpIrohToClient(region, slot, claim, stream);
  const [inputResult, outputResult] = await Promise.allSettled([input, output]);
  if (inputResult.status === "rejected") {
    stream.abort(inputResult.reason);
    closeWorkerError(region, slot, claim, ERROR_CLIENT_TO_IROH);
  } else if (outputResult.status === "rejected") {
    stream.abort(outputResult.reason);
    closeWorkerError(region, slot, claim, ERROR_IROH_TO_CLIENT);
  } else {
    closeWorkerOutput(region, slot, claim);
  }
}

function parseRegion(message: RegionMessage): Region {
  const match = /^iroh:\/\/([0-9a-f]{64})$/.exec(message.target);
  if (!match) throw new Error("adapter target must be a canonical iroh:// EndpointId");
  if (!(message.buffer instanceof SharedArrayBuffer)) throw new Error("adapter buffer must be shared");
  if (!Number.isSafeInteger(message.offset) || message.offset < 0 || (message.offset & 3) !== 0) {
    throw new Error("adapter region offset must be a non-negative aligned integer");
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
export function installIrohVgiAdapter(nodePromise: Promise<IrohNode>): () => void {
  const regions = new Map<string, Region>();
  let node: IrohNode | undefined;
  let polling = false;
  let installed = true;

  const poll = async (): Promise<void> => {
    if (polling || !node) return;
    polling = true;
    try {
      while (installed) {
        let active = false;
        for (const region of regions.values()) {
          if (region.stopped) continue;
          for (let slot = 0; slot < region.nSlots; slot++) {
            const claim = Atomics.load(region.words, slotWord(region, slot) + STATE);
            const lastClaim = region.running.get(slot);
            if (claim === 0) {
              if (lastClaim !== undefined) region.running.delete(slot);
              continue;
            }
            active = true;
            if (lastClaim !== claim) {
              region.running.set(slot, claim);
              // Retain the completed claim marker until STATE changes. A
              // failed open publishes one terminal error and must not redial
              // the same claim in a tight loop before the client releases it.
              void serveClaim(node, region, slot, claim);
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
        region.stopped = true;
        regions.delete(message.target);
      }
      return;
    }
    if (message.type !== "vgi-init" && message.type !== "vgi-register-target") return;

    void nodePromise.then(
      (resolvedNode) => {
        node = resolvedNode;
        const region = parseRegion(message);
        const old = regions.get(region.target);
        if (old) old.stopped = true;
        regions.set(region.target, region);
        void poll();
        if (message.type === "vgi-init") {
          self.postMessage({ type: "vgi-ready", endpointId: node.endpointId });
        } else {
          self.postMessage({ type: "vgi-target-ready", requestId: message.requestId });
        }
      },
      (error) => {
        const detail = error instanceof Error ? error.message : String(error);
        if (message.type === "vgi-init") self.postMessage({ type: "vgi-error", error: detail });
        else self.postMessage({ type: "vgi-target-error", requestId: message.requestId, error: detail });
      },
    );
  };
  self.addEventListener("message", onMessage as EventListener);
  return () => {
    installed = false;
    for (const region of regions.values()) region.stopped = true;
    regions.clear();
    self.removeEventListener("message", onMessage as EventListener);
  };
}
