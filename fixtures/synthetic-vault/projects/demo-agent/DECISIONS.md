---
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
