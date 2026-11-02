# Quickstart

This alpha release runs without external services.

## 1. Run The Gate

```bash
make ci
```

This runs:

- unit tests
- synthetic demo
- vault doctor
- MCP recall smoke
- live Control Center API smoke
- self-dogfood against this repo's docs
- private-context scan

Docker path:

```bash
docker compose --profile demo run --rm --build arvyx-demo
```

The production server intentionally refuses to start without a configured
bearer secret and initialized persistent volume. Follow
[`vps-deployment.md`](vps-deployment.md) for that path.

CI validates the Docker demo wiring without requiring a daemon:

```bash
make docker-compose-smoke
```

Release-host validation runs the authenticated server acceptance suite against
a real Docker Compose daemon:

```bash
make docker-runtime-smoke
```

Fallback when Docker is unavailable:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/arvyx demo --json
```

Editable install path:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/arvyx demo --vault fixtures/synthetic-vault --json
```

## 2. Create A Demo Vault

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli init /tmp/arvyx-demo-vault
```

## 3. Recall Before Expanding

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli recall \
  "what did we decide about safe mcp bridge" \
  --vault /tmp/arvyx-demo-vault \
  --project demo-agent \
  --json
```

Recall also includes deterministic semantic-lite matching for common agent-ops
phrases:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli recall \
  "which guardrail proxy protects credentials" \
  --vault /tmp/arvyx-demo-vault \
  --project demo-agent \
  --json
```

## 4. Expand Exact Sources Only When Needed

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli context-pack \
  "what did we decide about safe mcp bridge" \
  --vault /tmp/arvyx-demo-vault \
  --project demo-agent \
  --max-tokens 220 \
  --json
```

## 5. Use The MCP Tool Surface

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":"quickstart","method":"tools/call","params":{"name":"memory.recall","arguments":{"question":"what did we decide about safe mcp bridge","project":"demo-agent","max_tokens":120}}}' \
  | PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli mcp --profile read-only \
      --vault /tmp/arvyx-demo-vault
```

## 6. Run A Control-Plane Approval

```bash
state=/tmp/arvyx-control-events.jsonl
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault approval request \
  "arvyx recall demo-agent" \
  --state "$state" \
  --requester operator \
  --reason "quickstart approval flow" \
  --json
```

Use `approval.id` from that JSON response as `APPROVAL_ID` in both commands
below; it is not a literal ID. Approve and consume it with:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault approval approve \
  APPROVAL_ID \
  --state "$state" \
  --json

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault approval consume \
  APPROVAL_ID \
  "arvyx recall demo-agent" \
  --state "$state" \
  --json
```

Approval consumption requires the same command text that produced the stored
hash.

Summarize the append-only log before projecting or archiving it:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault store manifest \
  --state "$state" \
  --json
```

## 7. Import Markdown Memory

```bash
mkdir -p /tmp/arvyx-notes
printf '%s\n' 'Imported note: governed memory keeps markdown imports separate from current truth.' \
  > /tmp/arvyx-notes/operator-note.md

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli import markdown \
  /tmp/arvyx-notes \
  --vault /tmp/arvyx-demo-vault \
  --project demo-agent \
  --json
```

Imported notes land in `projects/demo-agent/imported/`, where recall can cite
them without promoting them into `STATUS.md` or `DECISIONS.md`.
Add `--dry-run` to preview planned import paths before writing. Duplicate
filenames are disambiguated instead of overwritten.

Compatibility importers keep source lanes separate:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli import obsidian \
  /tmp/arvyx-notes \
  --vault /tmp/arvyx-demo-vault \
  --project demo-agent \
  --json

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli import basic-memory \
  /tmp/arvyx-notes \
  --vault /tmp/arvyx-demo-vault \
  --project demo-agent \
  --json
```

## 8. Dogfood The Product Docs

Run the product against this repository's own public-safe docs:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli dogfood self --json
```

This creates a temporary governed vault, imports `README.md` and `docs/*.md`,
then verifies recall, context-pack, demo, and release evidence export from the
imported memory surface.

## 9. Dogfood The Live API

Run the same API through a real local HTTP server:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli dogfood live-api --json
```

This verifies `/health`, `/dashboard`, bearer-protected recall, MCP tool
listing, and task round-trip behavior over an actual socket.

## 10. Run A Release Candidate Report

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli release-candidate --json
```

The report may approve local/private operation while keeping publication
blocked until multi-model review and release-gate status are complete.

Collect release-host-only posture:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli release-host --json
```

Run the Docker and real MCP client version on the actual release host before
public review:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli release-host \
  --run-docker \
  --mcp-client-evidence tmp/mcp-client-evidence.json \
  --json
```

On the release host, pass the same host checks into the release bundle with:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli evidence export \
  --run-docker \
  --mcp-client-evidence tmp/mcp-client-evidence.json \
  --output tmp/evidence.json \
  --json
```

Use `examples/mcp-clients/real-client-evidence.example.json` as the schema
reference for `tmp/mcp-client-evidence.json`.

Generate a validated local evidence file with:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli evidence mcp-client \
  --output tmp/mcp-client-evidence.json \
  --json
```

Pass that file into the candidate report when you want host evidence reflected
in release blockers:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli release-candidate \
  --mcp-client-evidence tmp/mcp-client-evidence.json \
  --json
```

## 11. Run The Operator Surface

Serve the local dashboard with the operator MCP profile:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli serve-api \
  --host 127.0.0.1 \
  --port 8765 \
  --delivery-routes config/agent-delivery-routes.example.json \
  --mcp-profile operator
```

Open:

```text
http://127.0.0.1:8765/dashboard
```

The dashboard uses synthetic state by default. Keep real machine-specific clone
paths and registry mappings in private memory, not in this repository.

## 12. Run The War Room Loop

The one-command demo now exercises this whole loop on scratch state:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli demo \
  --vault fixtures/synthetic-vault --json
```

To run it manually, post an actionable thread, watch it in the pending inbox,
acknowledge, and finish it:

```bash
state=/tmp/arvyx-thread-events.jsonl
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault thread post \
  --to vesper --channel demo-agent --type ask \
  --actor operator \
  --title "Daily health check" --text "Run synthetic checks." \
  --state "$state" --json

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault thread pending vesper \
  --state "$state" --json
```

Use `thread.id` from the post response as `THREAD_ID` below (not a literal ID).
Ack and complete it (ack keeps it pending; done clears it):

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault thread ack THREAD_ID \
  --actor vesper --text "Taking this." --state "$state" --json

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault thread done THREAD_ID \
  --actor vesper --text "Done with receipts." --state "$state" --json
```

Create the day's health handoff threads (rerunning the same date skips instead
of duplicating), then compute notification candidates without sending anything:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault health daily-handoff --config examples/local-dev/daily-handoff.example.json \
  --state "$state" --json

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault health notify-check \
  --state "$state" --dry-run --json
```

Deliver for real through the safe default (stdout) or a local JSONL delivery
log; dedupe state lives in the same append-only event log:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault /tmp/arvyx-demo-vault health notify-check \
  --state "$state" --adapter file --deliveries /tmp/arvyx-deliveries.jsonl --json
```

See [notifiers.md](notifiers.md) for the webhook and Telegram adapters and
their safety gates.
