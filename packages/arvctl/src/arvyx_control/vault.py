from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import tempfile

from .control import (
    accept_handoff,
    acknowledge_thread,
    complete_handoff,
    complete_task,
    complete_thread,
    approve_request,
    consume_approval,
    create_handoff,
    create_task,
    list_approvals,
    list_bus_messages,
    list_handoffs,
    list_pending_threads,
    list_tasks,
    post_bus_message,
    post_thread,
    read_all_threads,
    request_approval,
)
from .api import handle_api_request
from .health_ops import daily_handoff, notify_check
from .mcp import handle_request
from .notifiers import notify_and_deliver
from .recall import context_pack, excerpt, recall
from .store import sync_sqlite


VAULT_MARKER = ".arvyx-vault"

TEMPLATE_FILES = {
    VAULT_MARKER: """arvyx-vault-format: 1
""",
    "README.md": """# Synthetic Vault Fixture

Public-safe fixture data for tests and demos.
""",
    "agents/demobot/MEMORY.md": """---
id: demobot
type: agent-memory
tags: [demo, agent]
---

# Demo Bot Memory

Demo Bot is a synthetic demo agent.

Demo Bot prefers compact cited recall before reading full documents. Demo Bot works
on [[Demo Agent Project - Overview]] through governed memory tools.
""",
    "projects/demo-agent/OVERVIEW.md": """---
id: demo-agent
type: project-overview
tags: [demo, memory, control-plane]
---

# Demo Agent Project - Overview

Demo Agent Project is a synthetic fixture used to demonstrate governed memory
for an agent team.

See [[Demo Agent Project - Status]], [[Demo Agent Project - Decisions]], and
[[Demo Agent Project - Runbook]] for the current truth, decisions, and operating
steps.
""",
    "projects/demo-agent/STATUS.md": """---
id: demo-agent
type: project-status
tags: [demo, current-truth]
---

# Demo Agent Project - Status

## Current Truth

- The safety bridge sits between stdio clients and HTTP MCP servers.
- Recall should return compact answers with citations before any full document
  expansion.
""",
    "projects/demo-agent/DECISIONS.md": """---
id: demo-agent
type: project-decisions
tags: [demo, decisions]
---

# Demo Agent Project - Decisions

## 2026-07-01 - Safety Bridge Belongs To The Memory Plane

- Decision: the safe MCP bridge is part of the memory and control plane, not a
  standalone transport proxy.
- Reason: it injects authentication at the HTTP boundary, filters tool
  discovery, blocks write-shaped calls before they reach the upstream, and keeps
  audit output free of credential material.
""",
    "projects/demo-agent/RUNBOOK.md": """---
id: demo-agent
type: project-runbook
tags: [demo, runbook]
---

# Demo Agent Project - Runbook

## Recall Smoke

Run `arvyx recall` before expanding exact excerpts.
""",
    "projects/demo-agent/OPEN_QUESTIONS.md": """---
id: demo-agent
type: project-open-questions
tags: [demo, questions]
---

# Demo Agent Project - Open Questions

- Which embedding backend should power hybrid recall?
""",
    "projects/demo-agent/raw/private-draft.md": """# Private Draft

This raw note says raw-only-marker-761 and exists only to prove recall does not
read raw lanes.
""",
    "projects/demo-agent/archive/old.md": """# Archived Draft

This archived note says raw-only-marker-761 and exists only to prove recall does
not read archive lanes.
""",
    "agents/vesper/MEMORY.md": """---
id: vesper
type: agent-memory
tags: [demo, agent]
---

# Vesper Memory

Vesper is a synthetic demo agent that operates the message relay.

Vesper checks queue depth before restarting workers and records every
operational change as a handoff to the operator.
""",
    "projects/relay-ops/OVERVIEW.md": """---
id: relay-ops
type: project-overview
tags: [demo, relay, operations]
---

# Relay Ops Project - Overview

Relay Ops is a synthetic fixture project that moves messages between
machines through a store-and-forward relay.

See [[Relay Ops Project - Status]], [[Relay Ops Project - Decisions]], and
[[Relay Ops Project - Runbook]] for current truth, decisions, and operating
steps.
""",
    "projects/relay-ops/STATUS.md": """---
id: relay-ops
type: project-status
tags: [demo, current-truth]
---

# Relay Ops Project - Status

## Current Truth

- The relay heartbeat cadence is thirty seconds per machine.
- A standby machine is promoted after two consecutive missed heartbeats.
- The delivery queue is drained nightly and must stay below one hundred
  entries during business hours.
""",
    "projects/relay-ops/DECISIONS.md": """---
id: relay-ops
type: project-decisions
tags: [demo, decisions]
---

# Relay Ops Project - Decisions

## 2026-07-02 - Exactly-Once Delivery Uses Idempotency Keys

- Decision: exactly-once delivery is enforced with idempotency keys on the
  producer side, not with a deduplication sweep on the consumer side.
- Reason: consumer-side sweeps hide producer bugs and add unbounded reprocessing
  cost, while idempotency keys fail loudly at the source.

## 2026-07-03 - Relay Tokens Rotate Weekly

- Decision: relay worker tokens are rotated every week by the operator.
- Reason: short-lived credentials bound the blast radius of a leaked worker
  token without requiring per-request signing.
""",
    "projects/relay-ops/RUNBOOK.md": """---
id: relay-ops
type: project-runbook
tags: [demo, runbook]
---

# Relay Ops Project - Runbook

## Worker Restart

1. Confirm the delivery queue depth is below one hundred entries.
2. Stop the relay worker on the affected machine.
3. Start the worker and watch two heartbeat cycles before leaving.
""",
    "projects/relay-ops/OPEN_QUESTIONS.md": """---
id: relay-ops
type: project-open-questions
tags: [demo, questions]
---

# Relay Ops Project - Open Questions

- Should backpressure pause producers instead of shedding messages when the
  queue passes its limit?
""",
    "registry/agents/demobot.json": """{
  "id": "demobot",
  "display_name": "Demo Bot",
  "machine_id": "laptop-a",
  "runtime_id": "codex-demo",
  "scopes": ["memory.read", "memory.suggest"]
}
""",
    "registry/agents/vesper.json": """{
  "id": "vesper",
  "display_name": "Vesper",
  "machine_id": "server-b",
  "runtime_id": "claude-demo",
  "scopes": ["memory.read", "memory.suggest", "control.write"]
}
""",
    "registry/agents/backup-1.json": """{
  "id": "backup-1",
  "display_name": "Backup Host 1",
  "machine_id": "server-b",
  "runtime_id": "codex-demo",
  "scopes": ["replica.read"]
}
""",
    "registry/machines/server-b.json": """{
  "id": "server-b",
  "display_name": "Server B",
  "role": "relay-host"
}
""",
    "registry/runtimes/claude-demo.json": """{
  "id": "claude-demo",
  "display_name": "Claude Demo Runtime",
  "harness": "claude"
}
""",
    "registry/projects/relay-ops.json": """{
  "id": "relay-ops",
  "display_name": "Relay Ops Project",
  "owner_agent_id": "vesper"
}
""",
    "registry/machines/laptop-a.json": """{
  "id": "laptop-a",
  "display_name": "Laptop A",
  "role": "operator-workstation"
}
""",
    "registry/runtimes/codex-demo.json": """{
  "id": "codex-demo",
  "display_name": "Codex Demo Runtime",
  "harness": "codex"
}
""",
    "registry/projects/demo-agent.json": """{
  "id": "demo-agent",
  "display_name": "Demo Agent Project",
  "owner_agent_id": "demobot"
}
""",
    "policies/README.md": "# Policies\n\nSynthetic policy placeholder.\n",
    "shared/runbooks/README.md": "# Shared Runbooks\n\nSynthetic runbook placeholder.\n",
}


@dataclass(frozen=True)
class InitResult:
    path: str
    files_created: list[str]

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "files_created": self.files_created}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class DemoResult:
    ok: bool
    checks: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "checks": self.checks}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def init_vault(path: Path, force: bool = False) -> InitResult:
    if path.exists() and any(path.iterdir()):
        if not force:
            raise FileExistsError(f"target is not empty: {path}")
        if not (path / VAULT_MARKER).exists():
            raise ValueError(
                f"refusing to delete {path}: not an Arvyx vault "
                f"(no {VAULT_MARKER} marker); remove the directory manually if intended"
            )
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)

    created: list[str] = []
    for relative, content in TEMPLATE_FILES.items():
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        created.append(relative)
    return InitResult(path=str(path), files_created=created)


def run_demo(vault: Path) -> DemoResult:
    from contextvars import Context
    from .replica_authority import authority_context

    # This helper owns a private state, independent of the caller's CLI/test
    # domain. Bind it in a fresh synchronous context, not by replacing an
    # existing authority binding or guessing a state outside this owner.
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "control-events.jsonl"

        def execute() -> DemoResult:
            with authority_context(vault, state):
                checks: list[dict[str, object]] = []

                recall_result = recall(
                    "what did we decide about safe mcp bridge",
                    vault=vault,
                    project="demo-agent",
                    max_tokens=120,
                )
                checks.append(
                    {
                        "name": "recall",
                        "ok": bool(recall_result.answer and recall_result.sources),
                        "sources": [source.path for source in recall_result.sources],
                    }
                )

                pack_result = context_pack(
                    "what did we decide about safe mcp bridge",
                    vault=vault,
                    project="demo-agent",
                    max_tokens=200,
                )
                checks.append(
                    {
                        "name": "context_pack",
                        "ok": bool(pack_result.answer and pack_result.excerpts),
                        "excerpt_count": len(pack_result.excerpts),
                    }
                )

                try:
                    excerpt(
                        vault=vault,
                        source_path="projects/demo-agent/raw/private-draft.md",
                        lines="1-2",
                    )
                except ValueError:
                    forbidden_ok = True
                else:
                    forbidden_ok = False
                checks.append({"name": "forbidden_path_refused", "ok": forbidden_ok})

                mcp_response = handle_request(
                    {
                        "jsonrpc": "2.0",
                        "id": "demo-recall",
                        "method": "tools/call",
                        "params": {
                            "name": "memory.recall",
                            "arguments": {
                                "question": "what did we decide about safe mcp bridge",
                                "project": "demo-agent",
                                "max_tokens": 120,
                            },
                        },
                    },
                    vault=vault,
                    state=state,
                )
                structured = mcp_response.get("result", {}).get("structuredContent", {})
                checks.append(
                    {
                        "name": "mcp_recall",
                        "ok": bool(structured.get("answer") and structured.get("sources")),
                        "tool": "memory.recall",
                    }
                )

                created = create_task(state=state, title="Review demo memory recall", owner="demobot")
                complete_task(state=state, task_id=created.task.id)
                projected = list_tasks(state=state)
                checks.append(
                    {
                        "name": "control_tasks",
                        "ok": len(projected.tasks) == 1 and projected.tasks[0].status == "done",
                        "event_log_exists": state.exists(),
                    }
                )
                requested = request_approval(
                    state=state,
                    command="arvyx recall demo-agent",
                    requester="demobot",
                    reason="demo approval flow",
                )
                approve_request(state=state, approval_id=requested.approval.id, approver="operator")
                consume_approval(state=state, approval_id=requested.approval.id, command="arvyx recall demo-agent")
                approvals = list_approvals(state=state)
                checks.append(
                    {
                        "name": "control_approvals",
                        "ok": len(approvals.approvals) == 1 and approvals.approvals[0].status == "consumed",
                        "command_hash": approvals.approvals[0].command_hash if approvals.approvals else "",
                    }
                )
                handoff = create_handoff(
                    state=state,
                    title="Continue demo operations",
                    from_agent="demobot",
                    to_agent="operator",
                    summary="Synthetic handoff for control-plane demo.",
                )
                accept_handoff(state=state, handoff_id=handoff.handoff.id)
                complete_handoff(state=state, handoff_id=handoff.handoff.id)
                handoffs = list_handoffs(state=state)
                checks.append(
                    {
                        "name": "control_handoffs",
                        "ok": len(handoffs.handoffs) == 1 and handoffs.handoffs[0].status == "completed",
                        "handoff_id": handoffs.handoffs[0].id if handoffs.handoffs else "",
                    }
                )
                post_bus_message(
                    state=state,
                    message="Demo bus message for operator coordination.",
                    channel="ops",
                    actor="demobot",
                    severity="notice",
                )
                bus_messages = list_bus_messages(state=state, channel="ops")
                checks.append(
                    {
                        "name": "control_bus",
                        "ok": len(bus_messages.messages) == 1 and bus_messages.messages[0].channel == "ops",
                        "message_id": bus_messages.messages[0].id if bus_messages.messages else "",
                    }
                )
                sqlite_result = sync_sqlite(state=state, db=Path(tmp) / "control.sqlite")
                checks.append(
                    {
                        "name": "control_store",
                        "ok": (
                            sqlite_result.events == 9
                            and sqlite_result.tasks == 1
                            and sqlite_result.approvals == 1
                            and sqlite_result.handoffs == 1
                            and sqlite_result.bus_messages == 1
                        ),
                        "db": sqlite_result.db,
                    }
                )
                api_response = handle_api_request(
                    "POST",
                    "/memory/recall",
                    {
                        "question": "which guardrail proxy protects credentials",
                        "project": "demo-agent",
                        "max_tokens": 120,
                    },
                    vault=vault,
                    state=state,
                )
                checks.append(
                    {
                        "name": "control_api",
                        "ok": api_response.status == 200 and bool(api_response.body.get("sources")),
                        "status": api_response.status,
                    }
                )

                thread = post_thread(
                    state=state,
                    title="Run the demo War Room loop",
                    body="Synthetic War Room thread for the product demo.",
                    thread_type="ask",
                    actor="demobot",
                    target="vesper",
                    channel="demo-agent",
                ).thread
                pending_after_post = list_pending_threads(state=state, target="vesper").threads
                acknowledge_thread(state=state, thread_id=thread.id, actor="vesper", text="Acknowledged for demo.")
                pending_after_ack = list_pending_threads(state=state, target="vesper").threads
                complete_thread(state=state, thread_id=thread.id, actor="vesper", text="Completed with synthetic receipts.")
                pending_after_done = list_pending_threads(state=state, target="vesper").threads
                checks.append(
                    {
                        "name": "thread_war_room_loop",
                        "ok": (
                            any(item.id == thread.id for item in pending_after_post)
                            and any(item.id == thread.id for item in pending_after_ack)
                            and all(item.id != thread.id for item in pending_after_done)
                        ),
                        "thread_id": thread.id,
                    }
                )

                informational = post_thread(
                    state=state,
                    title="Demo status update",
                    body="Synthetic informational status thread.",
                    thread_type="status",
                    actor="demobot",
                    target="vesper",
                    channel="demo-agent",
                ).thread
                marked_read = read_all_threads(state=state, target="vesper").threads
                checks.append(
                    {
                        "name": "thread_read_all",
                        "ok": any(thread.id == informational.id and not thread.unread for thread in marked_read),
                        "marked": [thread.id for thread in marked_read],
                    }
                )

                from .health_ops import DEFAULT_DAILY_ROLES
                roles_config = Path(tmp) / "demo-roles.json"
                roles_config.write_text(json.dumps({"roles": DEFAULT_DAILY_ROLES}), encoding="utf-8", newline="\n")
                first_handoff = daily_handoff(state=state, date="2026-01-01", config=roles_config)
                second_handoff = daily_handoff(state=state, date="2026-01-01", config=roles_config)
                checks.append(
                    {
                        "name": "health_daily_handoff",
                        "ok": len(first_handoff.created) == 4 and len(second_handoff.created) == 0 and len(second_handoff.skipped) == 4,
                        "created": len(first_handoff.created),
                        "skipped_on_rerun": len(second_handoff.skipped),
                    }
                )

                dry_run_notifications = notify_check(state=state, dry_run=True)
                notification_events_before_delivery = _count_event_type(state, "thread.notification_sent")
                deliveries_path = Path(tmp) / "deliveries.jsonl"
                file_delivery = notify_and_deliver(
                    state=state,
                    adapter="file",
                    deliveries_path=deliveries_path,
                    quiet_stdout=True,
                )
                notification_events_after_delivery = _count_event_type(state, "thread.notification_sent")
                suppressed_after_delivery = notify_check(state=state).candidates
                checks.append(
                    {
                        "name": "health_notify_loop",
                        "ok": (
                            dry_run_notifications.dry_run
                            and bool(dry_run_notifications.candidates)
                            and notification_events_before_delivery == 0
                            and file_delivery.ok
                            and len(file_delivery.deliveries) == len(file_delivery.candidates)
                            and notification_events_after_delivery == len(file_delivery.candidates)
                            and deliveries_path.exists()
                            and not suppressed_after_delivery
                        ),
                        "candidates": len(dry_run_notifications.candidates),
                        "deliveries": len(file_delivery.deliveries),
                        "notification_events": notification_events_after_delivery,
                    }
                )

                return DemoResult(ok=all(bool(check["ok"]) for check in checks), checks=checks)

        return Context().run(execute)


def _count_event_type(state: Path, event_type: str) -> int:
    if not state.exists():
        return 0
    count = 0
    for line in state.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == event_type:
            count += 1
    return count
