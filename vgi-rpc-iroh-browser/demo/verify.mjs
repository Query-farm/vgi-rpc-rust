#!/usr/bin/env node
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";

const url = process.argv[2];
if (!url) throw new Error("usage: node verify.mjs <browser-url>");

const haybarn =
  process.env.HAYBARN_WASM ??
  join(homedir(), "Development", "haybarn", "haybarn-wasm");
const puppeteer = createRequire(join(haybarn, "package.json"))("puppeteer");

const browser = await puppeteer.launch({
  headless: "new",
  args: ["--no-sandbox"],
});
try {
  const page = await browser.newPage();
  page.on("console", (message) => {
    if (message.type() === "error") {
      console.error(`[browser] ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => console.error(`[browser] ${error.stack}`));
  await page.goto(url, { waitUntil: "networkidle0", timeout: 30_000 });
  const isolated = await page.evaluate(() => self.crossOriginIsolated);
  if (!isolated) throw new Error("browser page is not cross-origin isolated");
  await page.waitForFunction(() => window.__vgiIrohDemo?.done === true, {
    timeout: 120_000,
  });
  const outcome = await page.evaluate(() => ({
    demo: window.__vgiIrohDemo,
    status: document.querySelector("#status")?.textContent,
    log: document.querySelector("#log")?.textContent,
  }));
  if (outcome.demo?.error) throw new Error(outcome.demo.error);
  if (!/^[0-9a-f]{64}$/.test(outcome.demo?.browserEndpointId ?? "")) {
    throw new Error("browser did not report a canonical Iroh EndpointId");
  }
  if (!outcome.status?.startsWith("Done")) {
    throw new Error(`demo did not finish successfully: ${outcome.status}`);
  }
  console.log(outcome.log?.trim());
  console.log(`Verified browser Iroh identity: ${outcome.demo.browserEndpointId}`);
} finally {
  await browser.close();
}
