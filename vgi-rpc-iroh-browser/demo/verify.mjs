#!/usr/bin/env node
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const url = process.argv[2];
const engineName = process.argv[3] ?? "chrome";
if (!url)
  throw new Error(
    "usage: node verify.mjs <browser-url> [chrome|firefox|webkit|safari]",
  );

if (engineName === "safari") {
  await verifySafari(url);
} else {
  const browserPackage = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "js",
    "package.json",
  );
  const playwright = createRequire(browserPackage)("playwright");
  let browser;
  let browserLabel;
  if (engineName === "chrome") {
    browser = await playwright.chromium.launch({
      channel: "chrome",
      headless: true,
    });
    browserLabel = "Chrome";
  } else if (engineName === "firefox" || engineName === "webkit") {
    browser = await playwright[engineName].launch({ headless: true });
    browserLabel =
      engineName === "firefox"
        ? "Firefox"
        : "Playwright WebKit (not Apple Safari)";
  } else {
    throw new Error(`unsupported browser engine: ${engineName}`);
  }
  try {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on("console", (message) => {
      if (message.type() === "error") {
        console.error(`[browser] ${message.text()}`);
      }
    });
    page.on("pageerror", (error) => {
      pageErrors.push(error.stack ?? String(error));
      console.error(`[browser] ${error.stack}`);
    });
    await page.goto(url, {
      waitUntil: engineName === "chrome" ? "networkidle0" : "networkidle",
      timeout: 30_000,
    });
    const isolated = await page.evaluate(() => self.crossOriginIsolated);
    if (!isolated) throw new Error("browser page is not cross-origin isolated");
    const demoFinished = () => window.__vgiIrohDemo?.done === true;
    if (engineName === "chrome") {
      await page.waitForFunction(demoFinished, { timeout: 120_000 });
    } else {
      await page.waitForFunction(demoFinished, undefined, { timeout: 120_000 });
    }
    const outcome = await page.evaluate(() => ({
      demo: window.__vgiIrohDemo,
      status: document.querySelector("#status")?.textContent,
      log: document.querySelector("#log")?.textContent,
    }));
    assertOutcome(outcome, browserLabel, pageErrors);
  } finally {
    await browser.close();
  }
}

function assertOutcome(outcome, label, pageErrors = []) {
  if (outcome.demo?.error) {
    throw new Error(
      `${outcome.demo.error}\nstatus: ${outcome.status ?? "missing"}\n${outcome.log ?? ""}`,
    );
  }
  if (!/^[0-9a-f]{64}$/.test(outcome.demo?.browserEndpointId ?? "")) {
    throw new Error("browser did not report a canonical Iroh EndpointId");
  }
  if (!outcome.status?.startsWith("Done")) {
    throw new Error(`demo did not finish successfully: ${outcome.status}`);
  }
  if (pageErrors.length > 0) {
    throw new Error(
      `${label}: uncaught page error(s):\n${pageErrors.join("\n")}`,
    );
  }
  console.log(outcome.log?.trim());
  console.log(
    `${label}: verified browser Iroh identity ${outcome.demo.browserEndpointId}`,
  );
}

async function verifySafari(targetUrl) {
  if (process.platform !== "darwin") {
    throw new Error("Safari verification requires macOS");
  }
  const port = await unusedLocalPort();
  const driver = spawn("safaridriver", ["--port", String(port)], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let diagnostics = "";
  let driverError;
  driver.on("error", (error) => {
    driverError = error;
  });
  driver.stderr.setEncoding("utf8");
  driver.stderr.on("data", (chunk) => {
    diagnostics = (diagnostics + chunk).slice(-64 * 1024);
  });
  let sessionId;
  try {
    await waitForWebDriver(port, driver, () => driverError);
    const created = await webdriver(port, "/session", {
      method: "POST",
      body: JSON.stringify({
        capabilities: {
          alwaysMatch: { browserName: "Safari", platformName: "macOS" },
        },
      }),
    });
    sessionId = created.sessionId;
    if (!sessionId) throw new Error("safaridriver did not return a session id");
    const sessionPath = `/session/${encodeURIComponent(sessionId)}`;
    await webdriver(port, `${sessionPath}/url`, {
      method: "POST",
      body: JSON.stringify({ url: targetUrl }),
    });
    const deadline = Date.now() + 120_000;
    let done = false;
    while (Date.now() < deadline) {
      done = await executeSafari(
        port,
        sessionPath,
        "return window.__vgiIrohDemo?.done === true;",
      );
      if (done) break;
      await delay(250);
    }
    if (!done)
      throw new Error("Safari timed out waiting for the VGI Iroh demo");
    const isolated = await executeSafari(
      port,
      sessionPath,
      "return self.crossOriginIsolated;",
    );
    if (!isolated) throw new Error("Safari page is not cross-origin isolated");
    const outcome = await executeSafari(
      port,
      sessionPath,
      "return {demo: window.__vgiIrohDemo, status: document.querySelector('#status')?.textContent, log: document.querySelector('#log')?.textContent};",
    );
    assertOutcome(outcome, "Apple Safari");
  } catch (error) {
    const detail = diagnostics.trim();
    throw new Error(
      `${error instanceof Error ? error.message : String(error)}${detail ? `\n${detail}` : ""}`,
    );
  } finally {
    if (sessionId) {
      await webdriver(port, `/session/${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
      }).catch(() => {});
    }
    await stopChild(driver);
  }
}

async function executeSafari(port, sessionPath, script) {
  return webdriver(port, `${sessionPath}/execute/sync`, {
    method: "POST",
    body: JSON.stringify({ script, args: [] }),
  });
}

async function webdriver(port, path, init = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
  const payload = await response.json();
  if (!response.ok || payload.value?.error) {
    throw new Error(
      payload.value?.message ?? `WebDriver request failed: ${response.status}`,
    );
  }
  return payload.value;
}

async function waitForWebDriver(port, driver, getDriverError) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const driverError = getDriverError();
    if (driverError) throw driverError;
    if (driver.exitCode !== null || driver.signalCode !== null) {
      throw new Error(
        `safaridriver exited with ${driver.exitCode ?? driver.signalCode}`,
      );
    }
    try {
      await webdriver(port, "/status");
      return;
    } catch {
      await delay(100);
    }
  }
  throw new Error("timed out waiting for safaridriver");
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  if (await settlesWithin(exited, 3_000)) return;
  child.kill("SIGKILL");
  await settlesWithin(exited, 3_000);
}

async function settlesWithin(promise, milliseconds) {
  return Promise.race([
    promise.then(() => true),
    delay(milliseconds).then(() => false),
  ]);
}

function unusedLocalPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
