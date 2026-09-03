import { firefox, webkit } from "playwright";

const url = process.argv[2];
if (!url) throw new Error("usage: node run-generated-bindings-playwright.mjs <smoke-url>");

const engines = [
  ["Firefox", firefox],
  ["Playwright WebKit (not Apple Safari)", webkit],
];

for (const [name, engine] of engines) {
  const browser = await engine.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const browserErrors = [];
    page.on("console", (message) => {
      if (message.type() === "error") browserErrors.push(`console: ${message.text()}`);
    });
    page.on("pageerror", (error) => browserErrors.push(`page: ${error.stack ?? error}`));

    await page.goto(url, { waitUntil: "load" });
    await page.waitForFunction(
      () => {
        const result = document.body?.textContent ?? "";
        return result === "PASS" || result.startsWith("FAIL:");
      },
      undefined,
      { timeout: 10_000 },
    );
    const result = (await page.textContent("body"))?.trim();
    if (result !== "PASS") {
      throw new Error(`${name}: ${result ?? "missing result"}\n${browserErrors.join("\n")}`);
    }
    console.log(`${name}: PASS`);
  } finally {
    await browser.close();
  }
}
