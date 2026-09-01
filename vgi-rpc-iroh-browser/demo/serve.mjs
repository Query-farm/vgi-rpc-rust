#!/usr/bin/env node
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = resolve(process.env.DEMO_DIST ?? join(here, "dist"));
const port = Number(process.argv[2] ?? process.env.PORT ?? 8787);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
  throw new Error("port must be an integer from 1 through 65535");
}
if (!existsSync(join(root, "index.html"))) {
  throw new Error(`demo is not built: ${join(root, "index.html")}`);
}

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".wasm", "application/wasm"],
]);

const server = createServer((request, response) => {
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Cache-Control", "no-store");
  try {
    const pathname = decodeURIComponent(
      new URL(request.url ?? "/", "http://localhost").pathname,
    );
    const relative = normalize(pathname).replace(/^[/\\]+/, "");
    let file = resolve(root, relative || "index.html");
    if (file !== root && !file.startsWith(`${root}${sep}`)) {
      response.writeHead(403).end("forbidden");
      return;
    }
    if (existsSync(file) && statSync(file).isDirectory()) {
      file = join(file, "index.html");
    }
    if (!existsSync(file) || !statSync(file).isFile()) {
      response.writeHead(404).end("not found");
      return;
    }
    response.setHeader(
      "Content-Type",
      contentTypes.get(extname(file)) ?? "application/octet-stream",
    );
    response.writeHead(200);
    createReadStream(file).pipe(response);
  } catch (error) {
    response
      .writeHead(400)
      .end(error instanceof Error ? error.message : "bad request");
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`VGI Iroh browser demo: http://127.0.0.1:${port}/`);
});
