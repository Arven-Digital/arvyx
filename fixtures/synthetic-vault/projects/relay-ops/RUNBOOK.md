---
id: relay-ops
type: project-runbook
tags: [demo, runbook]
---

# Relay Ops Project - Runbook

## Worker Restart

1. Confirm the delivery queue depth is below one hundred entries.
2. Stop the relay worker on the affected machine.
3. Start the worker and watch two heartbeat cycles before leaving.
