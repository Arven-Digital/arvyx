---
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
