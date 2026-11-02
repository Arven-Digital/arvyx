import assert from "node:assert/strict";
import fs from "node:fs";

const html = fs.readFileSync(new URL("../src/arvyx_control/static/index.html", import.meta.url), "utf8");

function declaration(name) {
  const start = html.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `missing production function ${name}`);
  const brace = html.indexOf(") {", start) + 2;
  let depth = 0;
  for (let index = brace; index < html.length; index += 1) {
    if (html[index] === "{") depth += 1;
    if (html[index] === "}") depth -= 1;
    if (depth === 0) return html.slice(start, index + 1);
  }
  throw new Error(`unterminated production function ${name}`);
}

// The desk block runs from the presets to the first consumer; evaluate the
// dashboard's real code, closing over this harness's `model`.
const blockStart = html.indexOf("const DESK_PRESETS = ");
const blockEnd = html.indexOf("function visibleAgents(", blockStart);
assert.ok(blockStart !== -1 && blockEnd !== -1, "missing production desk block");
let model = null;
eval(`${html.slice(blockStart, blockEnd)}
${declaration("visibleAgents")}
${declaration("itemIsVisible")}
${declaration("warRoomAgents")}
${declaration("spriteName")}
globalThis.desks = { DESK_PRESETS, planDesks, agentMeta, isExcludedAgentId, visibleAgents, itemIsVisible, warRoomAgents, spriteName };`);
const { DESK_PRESETS, planDesks, agentMeta, isExcludedAgentId, visibleAgents, itemIsVisible, warRoomAgents, spriteName } = globalThis.desks;

const presetKeys = DESK_PRESETS.map((preset) => preset.key);
const agent = (id, dashboard) => ({ id, display_name: id.toUpperCase(), ...(dashboard ? { dashboard } : {}) });
const deskKeys = (plan) => Object.fromEntries(Array.from(plan.desks, ([id, desk]) => [id, desk.key]));

// Arbitrary ids with no registry hints: stable agent-id order fills the desks.
const arbitrary = ["zeta-9", "qq", "alpha", "m_1", "extra-5"].map((id) => agent(id));
const plain = planDesks(arbitrary);
assert.deepEqual(plain.warRoom, ["alpha", "extra-5", "m_1", "qq"], "first four ids by stable order get desks");
assert.deepEqual(deskKeys(plain), { alpha: presetKeys[0], "extra-5": presetKeys[1], m_1: presetKeys[2], qq: presetKeys[3] });
assert.ok(Array.from(plain.desks.values()).every((desk) => desk.configured === false), "auto-assigned desks say so");
assert.equal(plain.desks.has("zeta-9"), false, "overflow beyond the four desks gets no desk");
for (const order of [[...arbitrary].reverse(), [arbitrary[2], arbitrary[0], arbitrary[4], arbitrary[1], arbitrary[3]]]) {
  const again = planDesks(order);
  assert.deepEqual(again.warRoom, plain.warRoom, "assignment does not depend on API order");
  assert.deepEqual(deskKeys(again), deskKeys(plain), "desk keys do not depend on API order");
}

// Registry claims win; first claim by agent id wins a contested desk; unknown desks are ignored.
const claimed = planDesks([
  agent("zeta-9", { desk: "security" }),
  agent("qq", { desk: "security" }),
  agent("alpha", { desk: "not-a-desk" }),
  agent("m_1"),
  agent("extra-5"),
]);
assert.deepEqual(deskKeys(claimed), { qq: "security", alpha: "engineering", "extra-5": "research", m_1: "operations" });
assert.equal(claimed.desks.get("qq").configured, true);
assert.equal(claimed.desks.get("alpha").configured, false);
assert.deepEqual(claimed.warRoom, ["alpha", "qq", "extra-5", "m_1"], "war room renders in desk slot order");
const configuredOnly = planDesks([agent("b-2", { desk: "operations" }), agent("a-1", { desk: "engineering" })]);
assert.deepEqual(deskKeys(configuredOnly), { "a-1": "engineering", "b-2": "operations" });

// The operator fleet is the strict registry hint dashboard.squad === true; no agent is
// named in code. Other registry agents never take desks; strict hidden hints still work.
model = { agents: [agent("sage", { hidden: true, squad: true }), agent("Keeper", { squad: true }), agent("keeper", { squad: true }),
  agent("juniper", { hidden: "true", squad: true }), agent("kedik"), agent("unrelated", { squad: "true" })] };
assert.equal(isExcludedAgentId("unrelated"), true, "only a strict boolean squad hint joins the fleet");
assert.equal(isExcludedAgentId("SAGE"), true);
assert.equal(isExcludedAgentId("juniper"), false, "only a strict boolean hides a fleet agent");
assert.equal(isExcludedAgentId("kedik"), true);
assert.deepEqual(visibleAgents().map((a) => a.id), ["Keeper", "keeper", "juniper"]);
assert.equal(itemIsVisible({ owner: "juniper", acked_by: "sage" }), false);
assert.equal(itemIsVisible({ owner: "juniper", target: "operator" }), true);
// Hiding presence never suppresses pending operator governance.
assert.equal(itemIsVisible({ requester: "kedik", status: "requested" }), true);
assert.equal(itemIsVisible({ requester: "kedik", status: "approved" }), false);
assert.equal(itemIsVisible({ actor: "sage", target: "operator", pending: true }), true);
assert.equal(itemIsVisible({ actor: "sage", target: "operator", pending: false }), false);
assert.equal(itemIsVisible({ actor: "sage", target: "keeper", pending: true }), false);
assert.deepEqual(warRoomAgents().map((a) => a.id), ["juniper", "Keeper"], "duplicate ids share one desk");
assert.equal(spriteName("juniper"), presetKeys[0]);
assert.equal(spriteName("sage"), "generic");
assert.equal(agentMeta("juniper").label, "squad desk · auto-assigned");

// A fresh projection replaces the cached plan; configured desks label themselves.
model = { agents: [agent("juniper", { desk: "research", squad: true })] };
assert.equal(isExcludedAgentId("sage"), false, "plan follows the current projection");
assert.equal(spriteName("juniper"), "research");
assert.equal(agentMeta("juniper").label, `${DESK_PRESETS[2].role} · configured`);
model = null;
assert.deepEqual(warRoomAgents(), []);
assert.equal(agentMeta("anyone").sprite, "generic");

// Every preset has both sprite poses in the page.
for (const key of presetKeys) {
  for (const pose of [1, 2]) assert.ok(html.includes(`<symbol id="sprite-${key}-${pose}"`), `missing sprite ${key}-${pose}`);
}

console.log("dashboard desk assignment behavioral regression: PASS");
