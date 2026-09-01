import * as duckdb from "demo-haybarn";
import { installVgiWebWorkerBridge } from "demo-haybarn-vgi";

import { displayValue, parseEndpointId, requireSelect } from "./config.ts";

interface ArrowLikeResult {
  readonly numRows: number;
  readonly schema: {
    readonly fields: ReadonlyArray<{ readonly name: string }>;
  };
  getChildAt(index: number): { get(row: number): unknown } | null;
}

const endpointInput = required<HTMLInputElement>("endpoint-id");
const queryInput = required<HTMLTextAreaElement>("query");
const runButton = required<HTMLButtonElement>("run");
const status = required<HTMLElement>("status");
const logOutput = required<HTMLPreElement>("log");
const resultRoot = required<HTMLElement>("result");

let database: { terminate(): Promise<void> } | undefined;
let adapterWorker: Worker | undefined;
let browserEndpointId: string | undefined;

declare global {
  interface Window {
    __vgiIrohDemo?: {
      done: boolean;
      browserEndpointId?: string;
      rows?: unknown[][];
      error?: string;
    };
  }
}

window.__vgiIrohDemo = { done: false };

const endpointFromUrl = new URL(location.href).searchParams.get("endpoint");
if (endpointFromUrl) endpointInput.value = endpointFromUrl;
if (
  endpointFromUrl &&
  new URL(location.href).searchParams.get("autorun") === "1"
) {
  queueMicrotask(() => void runDemo());
}

runButton.addEventListener("click", () => void runDemo());
window.addEventListener("beforeunload", () => {
  adapterWorker?.terminate();
  void database?.terminate();
});

async function runDemo(): Promise<void> {
  window.__vgiIrohDemo = { done: false };
  runButton.disabled = true;
  resultRoot.replaceChildren();
  logOutput.textContent = "";
  try {
    if (!self.crossOriginIsolated || typeof SharedArrayBuffer === "undefined") {
      throw new Error(
        "cross-origin isolation is required; start this page with npm run serve",
      );
    }
    const endpointId = parseEndpointId(endpointInput.value);
    const query = requireSelect(queryInput.value);
    const target = `httpi://${endpointId}`;
    const nextUrl = new URL(location.href);
    nextUrl.searchParams.set("endpoint", endpointId);
    history.replaceState(null, "", nextUrl);

    setStatus("Starting the browser Iroh endpoint…");
    adapterWorker = new Worker(
      new URL("./adapter-worker.js", import.meta.url),
      {
        type: "module",
        name: "vgi-iroh-adapter",
      },
    );
    let resolveBrowserIdentity: (endpointId: string) => void;
    let rejectBrowserIdentity: (error: Error) => void;
    const browserIdentity = new Promise<string>((resolve, reject) => {
      resolveBrowserIdentity = resolve;
      rejectBrowserIdentity = reject;
    });
    adapterWorker.addEventListener("message", (event: MessageEvent) => {
      const message = event.data as
        { type?: string; endpointId?: string; error?: string } | undefined;
      if (message?.type === "demo-iroh-identity") {
        browserEndpointId = message.endpointId;
        appendLog(`Local browser EndpointId: ${message.endpointId}`);
        if (message.endpointId) resolveBrowserIdentity(message.endpointId);
      } else if (message?.type === "demo-iroh-error") {
        appendLog(`Iroh adapter error: ${message.error}`);
        rejectBrowserIdentity(
          new Error(message.error ?? "browser Iroh endpoint creation failed"),
        );
      }
    });

    const bundle = await duckdb.selectBundle({
      coi: {
        mainModule: "./duckdb-coi.wasm",
        mainWorker: "./duckdb-browser-coi.worker.js",
        pthreadWorker: "./duckdb-browser-coi.pthread.worker.js",
      },
    });
    const engineWorker = new Worker(bundle.mainWorker);
    installVgiWebWorkerBridge({
      irohAdapterWorker: adapterWorker,
      // The page authorizes only the EndpointId supplied in this form. SQL
      // cannot redirect the adapter to a different Iroh peer.
      resolveIrohTarget: (candidate: string) =>
        candidate === target ? candidate : null,
    })(engineWorker);

    setStatus("Starting Haybarn and loading VGI…");
    const db = new duckdb.AsyncDuckDB(new duckdb.ConsoleLogger(), engineWorker);
    database = db;
    await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
    await db.open({
      allowUnsignedExtensions: true,
      query: { castBigIntToDouble: false },
    });
    const connection = await db.connect();
    try {
      await connection.query(
        `SET custom_extension_repository='${location.origin}/extensions'`,
      );
      await connection.query("INSTALL vgi");
      await connection.query("LOAD vgi");
      appendLog("Loaded the VGI extension.");

      setStatus(`Attaching ${target}…`);
      await connection.query(
        `ATTACH 'example' AS remote (TYPE vgi, LOCATION '${target}')`,
      );
      appendLog("ATTACH completed; remote catalog discovery succeeded.");

      setStatus("Verifying the worker CallContext identity…");
      const identityResult = (await connection.query(
        "SELECT remote.main.whoami(1) AS principal",
      )) as ArrowLikeResult;
      if (identityResult.numRows !== 1) {
        throw new Error(
          `identity probe returned ${identityResult.numRows} rows instead of one`,
        );
      }
      const observedPrincipal = String(identityResult.getChildAt(0)?.get(0));
      const localIdentity = await browserIdentity;
      if (!observedPrincipal.endsWith(`/${localIdentity}`)) {
        throw new Error(
          "worker CallContext identity mismatch: " +
            `browser=${localIdentity}, worker=${observedPrincipal}`,
        );
      }
      appendLog(
        `Verified authenticated worker principal: ${observedPrincipal}`,
      );

      const functions = (await connection.query(
        "SELECT schema_name, function_name " +
          "FROM vgi_function_arguments() " +
          "WHERE catalog_name='remote' " +
          "GROUP BY ALL ORDER BY ALL",
      )) as ArrowLikeResult;
      appendLog(`Discovered ${functions.numRows} remote function(s).`);

      setStatus("Executing SELECT over httpi://…");
      appendLog(`SQL> ${query}`);
      const result = (await connection.query(query)) as ArrowLikeResult;
      renderResult(result);
      const rows = resultRows(result);
      window.__vgiIrohDemo = {
        done: true,
        browserEndpointId,
        rows,
      };
      setStatus(`Done — ${result.numRows} row(s).`, "ok");
    } finally {
      await connection.close();
    }
  } catch (error) {
    const detail =
      error instanceof Error ? (error.stack ?? error.message) : String(error);
    appendLog(detail);
    window.__vgiIrohDemo = {
      done: true,
      browserEndpointId,
      error: detail,
    };
    setStatus("Failed — see the log below.", "error");
  } finally {
    runButton.disabled = false;
  }
}

function resultRows(result: ArrowLikeResult): unknown[][] {
  return Array.from({ length: result.numRows }, (_, row) =>
    result.schema.fields.map((_, column) => result.getChildAt(column)?.get(row)),
  );
}

function renderResult(result: ArrowLikeResult): void {
  const table = document.createElement("table");
  const header = document.createElement("tr");
  for (const field of result.schema.fields) {
    const cell = document.createElement("th");
    cell.textContent = field.name;
    header.append(cell);
  }
  table.append(header);
  for (let row = 0; row < result.numRows; row++) {
    const tr = document.createElement("tr");
    for (let column = 0; column < result.schema.fields.length; column++) {
      const cell = document.createElement("td");
      cell.textContent = displayValue(result.getChildAt(column)?.get(row));
      tr.append(cell);
    }
    table.append(tr);
  }
  resultRoot.replaceChildren(table);
}

function required<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing #${id}`);
  return element as T;
}

function appendLog(message: string): void {
  logOutput.textContent += `${message}\n`;
}

function setStatus(message: string, state = "busy"): void {
  status.textContent = message;
  status.dataset.state = state;
}
