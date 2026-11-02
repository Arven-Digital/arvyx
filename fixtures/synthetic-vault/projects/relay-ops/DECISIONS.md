---
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
