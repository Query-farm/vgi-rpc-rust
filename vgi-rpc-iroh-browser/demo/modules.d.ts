declare module "demo-haybarn" {
  export function selectBundle(config: unknown): Promise<{
    mainModule: string;
    mainWorker: string;
    pthreadWorker?: string;
  }>;

  export class ConsoleLogger {}

  export class AsyncDuckDB {
    constructor(logger: ConsoleLogger, worker: Worker);
    instantiate(mainModule: string, pthreadWorker?: string): Promise<void>;
    open(options: unknown): Promise<void>;
    registerFileBuffer(name: string, buffer: Uint8Array): Promise<void>;
    connect(): Promise<{
      query(sql: string): Promise<unknown>;
      close(): Promise<void>;
    }>;
    terminate(): Promise<void>;
  }
}

declare module "demo-haybarn-vgi" {
  export function installVgiWebWorkerBridge(options: {
    irohAdapterWorker: Worker;
    resolveIrohTarget(candidate: string): string | null;
  }): (worker: Worker) => void;
}

declare module "demo-iroh-bindings" {
  interface WasmVgiStream {
    write(chunk: Uint8Array): Promise<void>;
    read(maxBytes: number): Promise<Uint8Array | undefined>;
    closeWrite(): Promise<void>;
    abort(): void;
  }

  interface WasmHttpResponse {
    readonly status: number;
    readonly headers: Array<readonly [string, string]>;
    read(): Promise<Uint8Array | undefined>;
    cancel(): void;
  }

  interface WasmIrohNode {
    readonly endpointId: string;
    openVgiStream(endpointId: string): Promise<WasmVgiStream>;
    fetchHttpi(
      endpointId: string,
      method: string,
      path: string,
      headers: Array<readonly [string, string]>,
      body: Uint8Array,
    ): Promise<WasmHttpResponse>;
    close(): Promise<void>;
  }

  export default function initWasm(): Promise<unknown>;
  export function createIrohNode(options?: {
    secretKey?: string;
    relayUrls?: string[];
  }): Promise<WasmIrohNode>;
}
