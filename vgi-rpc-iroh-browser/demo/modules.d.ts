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
  import type { WasmIrohNode } from "../js/index.ts";

  export default function initWasm(): Promise<unknown>;
  export function createIrohNode(options?: {
    secretKey?: string;
    relayUrls?: string[];
  }): Promise<WasmIrohNode>;
}
