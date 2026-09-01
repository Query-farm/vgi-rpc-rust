/** Browser-facing WHATWG stream wrapper for the wasm-bindgen transport. */

export type HeaderPair = readonly [name: string, value: string];
export type IrohProtocol = "vgi-rpc/arrow-mux/1" | "iroh-http/2";

export interface WasmVgiStream {
  write(chunk: Uint8Array): Promise<void>;
  read(maxBytes: number): Promise<Uint8Array | undefined>;
  closeWrite(): void;
  abort(): void;
}

export interface WasmHttpResponse {
  readonly status: number;
  readonly headers: HeaderPair[];
  read(): Promise<Uint8Array | undefined>;
  cancel(): void;
}

export interface WasmIrohNode {
  readonly endpointId: string;
  openVgiStream(endpointId: string): Promise<WasmVgiStream>;
  fetchHttpi(
    endpointId: string,
    method: string,
    path: string,
    headers: HeaderPair[],
    body: Uint8Array,
  ): Promise<WasmHttpResponse>;
  close(): Promise<void>;
}

export type TargetResolver = (
  target: string,
  protocol: IrohProtocol,
) => string | Promise<string>;

export interface VgiDuplexStream {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  abort(reason?: unknown): void;
}

export interface HttpiResponse {
  readonly status: number;
  /** Ordered fields; duplicate names, including Set-Cookie, are retained. */
  readonly headers: HeaderPair[];
  /** Raw HTTP representation bytes. Content decoding is the VGI client's job. */
  readonly body: ReadableStream<Uint8Array>;
  readonly bodyEncoding: "raw";
}

export type HttpiTransportStage =
  | "parse"
  | "resolve"
  | "connect"
  | "request"
  | "response_head"
  | "response_body";
export type HttpiTerminalCategory =
  | "invalid_request"
  | "unauthorized_target"
  | "unavailable"
  | "timeout"
  | "cancelled"
  | "protocol"
  | "transport"
  | "internal";
export type HttpiDispatchCertainty =
  | "not_dispatched"
  | "dispatched"
  | "ambiguous";

/** Stable transport evidence consumed by the SAB adapter; details stay sanitized. */
export class HttpiTransportError extends Error {
  readonly stage: HttpiTransportStage;
  readonly category: HttpiTerminalCategory;
  readonly dispatchCertainty: HttpiDispatchCertainty;

  constructor(
    stage: HttpiTransportStage,
    category: HttpiTerminalCategory,
    dispatchCertainty: HttpiDispatchCertainty,
    cause: unknown,
  ) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = "HttpiTransportError";
    this.stage = stage;
    this.category = category;
    this.dispatchCertainty = dispatchCertainty;
  }
}

export interface OpenOptions {
  signal?: AbortSignal;
  readChunkBytes?: number;
}

export interface CreateIrohOptions {
  /** Iroh 64-hex or z-base-32 secret key; omit for an ephemeral identity. */
  secretKey?: string;
  /** Replace the default n0 relay set. The array must not be empty. */
  relayUrls?: string[];
  /** Optional application-owned alias resolver and authorization boundary. */
  resolveTarget?: TargetResolver;
}

export type WasmIrohNodeFactory = (
  options?: Omit<CreateIrohOptions, "resolveTarget">,
) => Promise<WasmIrohNode>;

export async function createIrohNode(
  wasmFactory: WasmIrohNodeFactory,
  options: CreateIrohOptions = {},
): Promise<IrohNode> {
  const { resolveTarget, ...transportOptions } = options;
  return new IrohNode(await wasmFactory(transportOptions), resolveTarget);
}

/**
 * One application-owned Iroh identity.
 *
 * Share one instance per DuckDB engine. `resolveTarget` is optional: literal
 * 64-hex EndpointIds work by default, while applications that need aliases or
 * authorization can resolve/reject them without teaching VGI a policy system.
 */
export class IrohNode {
  constructor(
    private readonly wasm: WasmIrohNode,
    private readonly resolveTarget?: TargetResolver,
  ) {}

  get endpointId(): string {
    return this.wasm.endpointId;
  }

  private async resolve(
    target: string,
    protocol: IrohProtocol,
  ): Promise<string> {
    return this.resolveTarget ? this.resolveTarget(target, protocol) : target;
  }

  async openVgiStream(
    target: string,
    options: OpenOptions = {},
  ): Promise<VgiDuplexStream> {
    throwIfAborted(options.signal);
    const endpointId = await this.resolve(target, "vgi-rpc/arrow-mux/1");
    throwIfAborted(options.signal);
    const stream = await this.wasm.openVgiStream(endpointId);
    const chunkBytes = options.readChunkBytes ?? 64 * 1024;
    if (!Number.isSafeInteger(chunkBytes) || chunkBytes <= 0) {
      stream.abort();
      throw new RangeError("readChunkBytes must be a positive safe integer");
    }

    let aborted = false;
    const abortStream = () => {
      if (!aborted) {
        aborted = true;
        stream.abort();
      }
    };
    const onSignalAbort = () => abortStream();
    options.signal?.addEventListener("abort", onSignalAbort, { once: true });

    const readable = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          throwIfAborted(options.signal);
          const chunk = await stream.read(chunkBytes);
          if (chunk === undefined) {
            options.signal?.removeEventListener("abort", onSignalAbort);
            controller.close();
          } else {
            controller.enqueue(chunk);
          }
        } catch (error) {
          abortStream();
          controller.error(error);
        }
      },
      cancel() {
        abortStream();
      },
    });

    const writable = new WritableStream<Uint8Array>({
      async write(chunk) {
        throwIfAborted(options.signal);
        await stream.write(chunk);
      },
      close() {
        stream.closeWrite();
      },
      abort() {
        abortStream();
      },
    });
    return { readable, writable, abort: abortStream };
  }

  async fetchHttpi(
    target: string,
    method: string,
    path: string,
    headers: HeaderPair[],
    body: Uint8Array,
    signal?: AbortSignal,
  ): Promise<HttpiResponse> {
    try {
      throwIfAborted(signal);
    } catch (error) {
      throw new HttpiTransportError(
        "resolve",
        "cancelled",
        "not_dispatched",
        error,
      );
    }
    let endpointId: string;
    try {
      endpointId = await this.resolve(target, "iroh-http/2");
      throwIfAborted(signal);
    } catch (error) {
      throw new HttpiTransportError(
        "resolve",
        signal?.aborted ? "cancelled" : "unauthorized_target",
        "not_dispatched",
        error,
      );
    }
    let response: WasmHttpResponse;
    try {
      response = await this.wasm.fetchHttpi(
        endpointId,
        method,
        path,
        headers,
        body,
      );
    } catch (error) {
      const evidence = readHttpiEvidence(error);
      throw new HttpiTransportError(
        evidence?.stage ?? "request",
        evidence?.category ?? "transport",
        evidence?.dispatchCertainty ?? "ambiguous",
        error,
      );
    }
    const cancel = () => response.cancel();
    signal?.addEventListener("abort", cancel, { once: true });
    return {
      status: response.status,
      headers: response.headers,
      bodyEncoding: "raw",
      body: new ReadableStream<Uint8Array>({
        async pull(controller) {
          try {
            throwIfAborted(signal);
            const chunk = await response.read();
            if (chunk === undefined) {
              signal?.removeEventListener("abort", cancel);
              controller.close();
            } else {
              controller.enqueue(chunk);
            }
          } catch (error) {
            response.cancel();
            controller.error(error);
          }
        },
        cancel,
      }),
    };
  }

  close(): Promise<void> {
    return this.wasm.close();
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw (
      signal.reason ??
      new DOMException("The operation was aborted", "AbortError")
    );
  }
}

function readHttpiEvidence(error: unknown):
  | {
      stage: HttpiTransportStage;
      category: HttpiTerminalCategory;
      dispatchCertainty: HttpiDispatchCertainty;
    }
  | undefined {
  if (!error || typeof error !== "object") return undefined;
  const value = error as Record<string, unknown>;
  const stages: HttpiTransportStage[] = [
    "parse",
    "resolve",
    "connect",
    "request",
    "response_head",
    "response_body",
  ];
  const categories: HttpiTerminalCategory[] = [
    "invalid_request",
    "unauthorized_target",
    "unavailable",
    "timeout",
    "cancelled",
    "protocol",
    "transport",
    "internal",
  ];
  const certainties: HttpiDispatchCertainty[] = [
    "not_dispatched",
    "dispatched",
    "ambiguous",
  ];
  if (
    !stages.includes(value.vgiStage as HttpiTransportStage) ||
    !categories.includes(value.vgiCategory as HttpiTerminalCategory) ||
    !certainties.includes(value.vgiDispatchCertainty as HttpiDispatchCertainty)
  )
    return undefined;
  return {
    stage: value.vgiStage as HttpiTransportStage,
    category: value.vgiCategory as HttpiTerminalCategory,
    dispatchCertainty: value.vgiDispatchCertainty as HttpiDispatchCertainty,
  };
}
