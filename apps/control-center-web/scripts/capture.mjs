import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { randomUUID } from "node:crypto";

const ROOT = path.resolve(import.meta.dirname, "..");
const DIST = path.join(ROOT, "dist");
const OUT = path.join(ROOT, "evidence", "screenshots");
const BUILD = JSON.parse(await readFile(path.join(DIST, "build.json"), "utf8"));
const BUILD_ID = BUILD.build_id;
const COMMIT_ID = BUILD.commit_id;
const states = ["full", "empty", "loading", "error"];
const viewports = [{ width: 390, height: 844 }, { width: 768, height: 1024 }, { width: 1440, height: 1100 }];
const captureToken = randomUUID();
// The owned child binds port zero itself: no port-probe/rebind race and no
// acceptance of a pre-existing listener. Every response identifies this child.
const server = spawn("python", ["-u", "-c", `
import functools, http.server, sys
class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('X-AMC-Capture', sys.argv[2])
        super().end_headers()
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=sys.argv[1]))
print(server.server_port, flush=True)
server.serve_forever()
`, DIST, captureToken], { stdio: ["ignore", "pipe", "ignore"] });
let serverError;
server.on("error", error => { serverError = error; });
const portReady = new Promise((resolve, reject) => {
  let output = "";
  const timer = setTimeout(() => reject(new Error("capture child did not bind")), 10000);
  server.once("error", error => { clearTimeout(timer); reject(error); });
  server.once("exit", () => { clearTimeout(timer); reject(new Error("capture child exited")); });
  server.stdout.on("data", data => {
    output += data;
    if (output.includes("\n")) {
      clearTimeout(timer);
      if (!/^\d+\n$/.test(output)) return reject(new Error("invalid child port"));
      resolve(Number(output.trim()));
    }
  });
});
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
let browser;
try {
  const port = await portReady;
  const serverUp = await (async () => {
    for (let i = 0; i < 60; i++) {
      if (serverError || server.exitCode !== null || server.signalCode !== null) throw new Error("capture child unavailable");
      try {
        const response = await fetch(`http://127.0.0.1:${port}/build.json`, { signal: AbortSignal.timeout(2000), redirect: "error", cache: "no-store" });
        if (response.ok && response.headers.get("x-amc-capture") === captureToken && JSON.stringify(await response.json()) === JSON.stringify(BUILD)) return true;
      } catch {}
      await wait(250);
    }
    return false;
  })();
  if (!serverUp) throw new Error("synthetic server did not become ready");
  await mkdir(OUT, { recursive: true });
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_PATH || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const receipts = [];
  for (const viewport of viewports) {
    for (const state of states) {
      const page = await browser.newPage({ viewport, reducedMotion: "reduce" });
      try {
        const errors = [];
        page.on("console", msg => { if (msg.type() === "error") errors.push(msg.text()); });
        page.on("pageerror", error => errors.push(error.message));
        const response = await page.goto(`http://127.0.0.1:${port}/?state=${state}`, { waitUntil: "networkidle" });
        if (server.exitCode !== null || server.signalCode !== null || !response?.ok() || (await response.headerValue("x-amc-capture")) !== captureToken) throw new Error("capture response is not from owned child");
        await page.locator("#app[aria-busy='false']").waitFor();
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
        if (overflow || errors.length) throw new Error(`${viewport.width}/${state}: overflow=${overflow}, errors=${errors.join(" | ")}`);
        const filename = `observatory_${viewport.width}x${viewport.height}_${state}_${BUILD_ID}_${COMMIT_ID}.png`;
        await page.screenshot({ path: path.join(OUT, filename), fullPage: true });
        receipts.push({ viewport: `${viewport.width}x${viewport.height}`, state, build_id: BUILD_ID, commit_id: COMMIT_ID, file: filename, overflow: false, console_errors: 0 });
      } finally {
        await page.close().catch(() => {});
      }
    }
  }
  console.log(JSON.stringify({ ok: true, exercised: ["full/empty/loading/error", "390/768/1440", "reduced-motion", "horizontal-overflow", "console-errors", "stamped-screenshots"], screenshots: receipts }, null, 2));
} finally {
  if (browser) await browser.close().catch(() => {});
  if (server.exitCode === null && server.signalCode === null) server.kill("SIGTERM");
  const exited = await new Promise(resolve => {
    if (server.exitCode !== null || server.signalCode !== null) return resolve(true);
    server.once("exit", () => resolve(true));
    setTimeout(() => resolve(false), 5000).unref?.();
  });
  if (!exited) server.kill("SIGKILL");
}
