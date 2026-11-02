import assert from "node:assert/strict";
import fs from "node:fs";

const html = fs.readFileSync(new URL("../src/arvyx_control/static/index.html", import.meta.url), "utf8");

function declaration(name) {
  const functionStart = html.indexOf(`function ${name}(`);
  assert.notEqual(functionStart, -1, `missing production function ${name}`);
  const start = html.slice(Math.max(0, functionStart - 6), functionStart) === "async " ? functionStart - 6 : functionStart;
  const signatureEnd = html.indexOf(") {", functionStart);
  assert.notEqual(signatureEnd, -1, `missing body for production function ${name}`);
  const brace = signatureEnd + 2;
  let depth = 0;
  for (let index = brace; index < html.length; index += 1) {
    if (html[index] === "{") depth += 1;
    if (html[index] === "}") depth -= 1;
    if (depth === 0) return html.slice(start, index + 1);
  }
  throw new Error(`unterminated production function ${name}`);
}

const stateStart = html.indexOf("const workbench = {");
const stateEnd = html.indexOf("function selectedExecution", stateStart);
assert.notEqual(stateStart, -1, "missing production workbench state");

const buttons = Object.fromEntries(
  ["workbench-steer", "workbench-cancel", "workbench-resume"].map((id) => [id, {
    disabled: false,
    classList: { toggle() {} },
  }]),
);
const $ = (id) => buttons[id];
const setText = () => {};
const renderWorkbenchNavigator = () => {};
const renderWorkbenchEvents = () => {};
const renderWorkbenchInspector = () => {};
const matchMedia = () => ({ matches: false });
const activateWorkbenchTab = () => {};
let apiImpl;
const api = (...args) => apiImpl(...args);

// Execute the dashboard's actual state and refresh/control functions in this browser-like harness.
eval(`${html.slice(stateStart, stateEnd)}
${declaration("selectedExecution")}
${declaration("renderWorkbenchControls")}
function renderWorkbench() { renderWorkbenchControls(); }
${declaration("loadWorkbenchEvents")}
${declaration("refreshWorkbench")}
globalThis.productionWorkbench = { workbench, renderWorkbenchControls, refreshWorkbench };`);
const { workbench, renderWorkbenchControls, refreshWorkbench } = globalThis.productionWorkbench;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}
function assertAllDisabled(message) {
  for (const [id, button] of Object.entries(buttons)) assert.equal(button.disabled, true, `${message}: ${id}`);
}
function leasedExecution() {
  return { id: "exec-1", status: "leased", attempt_id: "attempt-1", target: "agent" };
}
async function tick() {
  await Promise.resolve();
  await Promise.resolve();
}

workbench.executions = [leasedExecution()];
workbench.selectedId = "exec-1";
workbench.events = [{ id: "old-event" }];
renderWorkbenchControls();
assert.equal(buttons["workbench-steer"].disabled, false, "precondition: steering starts enabled");
assert.equal(buttons["workbench-cancel"].disabled, false, "precondition: cancel starts enabled");

const failedTimeline = deferred();
apiImpl = (path) => path === "/executions"
  ? Promise.resolve({ executions: [leasedExecution()] })
  : failedTimeline.promise;
const failedRefresh = refreshWorkbench();
assertAllDisabled("list pending");
await tick();
assertAllDisabled("list succeeded but selected timeline pending");
failedTimeline.reject(new Error("timeline offline"));
assert.equal(await failedRefresh, false, "refresh must report failure when selected timeline fails");
assertAllDisabled("selected timeline failed");
assert.equal(workbench.listError, "", "successful list clears only the list error");
assert.equal(workbench.timelineError, "timeline offline", "timeline error is preserved independently");

const successfulTimeline = deferred();
apiImpl = (path) => path === "/executions"
  ? Promise.resolve({ executions: [leasedExecution()] })
  : successfulTimeline.promise;
const successfulRefresh = refreshWorkbench();
await tick();
assertAllDisabled("retry list succeeded but selected timeline still pending");
successfulTimeline.resolve({ events: [{ id: "fresh-event" }], next_cursor: "cursor", has_more: false });
assert.equal(await successfulRefresh, true, "refresh succeeds only after both authoritative reads");
assert.equal(buttons["workbench-steer"].disabled, false, "steering enables after fresh timeline succeeds");
assert.equal(buttons["workbench-cancel"].disabled, false, "cancel enables after fresh timeline succeeds");
assert.equal(buttons["workbench-resume"].disabled, true, "status-inapplicable resume remains disabled");
assert.deepEqual(workbench.events, [{ id: "fresh-event" }], "fresh timeline replaces stale events");

apiImpl = () => Promise.resolve({ executions: [] });
assert.equal(await refreshWorkbench(), true, "an empty list is a successful authoritative refresh");
assert.equal(workbench.selectedId, null, "invalid selection is cleared");
assertAllDisabled("no execution selected");

console.log("workbench refresh behavioral regression: PASS");
