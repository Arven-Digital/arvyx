import { chromium } from "playwright";
import { spawn } from "node:child_process";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const server = spawn("python", ["-m", "http.server", "4178", "--bind", "127.0.0.1", "--directory", path.join(ROOT, "dist")], { stdio: "ignore" });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
try {
  await wait(500);
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_PATH || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, reducedMotion: "reduce" });
  for (const state of ["full", "empty", "loading", "error"]) {
    await page.goto(`http://127.0.0.1:4178/?state=${state}`, { waitUntil: "networkidle" });
    await page.locator("#app[aria-busy='false']").waitFor();
    if (!(await page.title()).endsWith(state)) throw new Error(`title did not reflect ${state}`);
    const selectName = await page.locator("#state-select").getAttribute("aria-label");
    if (selectName !== "Replay state") throw new Error("state selector lacks accessible name");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    if (overflow) throw new Error(`horizontal overflow in ${state}`);
  }
  await page.goto("http://127.0.0.1:4178/?state=full", { waitUntil: "networkidle" });
  for (const text of ["current truth", "pending suggestion", "Scoped agent tools", "awaiting human", "Handoff & execution", "Cited basis", "audit receipt"]) {
    if (!(await page.getByText(text, { exact: false }).count())) throw new Error(`missing story surface: ${text}`);
  }
  await browser.close();
  console.log("smoke: PASS\nexercised: 4 replay states, responsive overflow, accessible selector, 7 control-center concepts, reduced motion");
} finally { server.kill("SIGTERM"); }
