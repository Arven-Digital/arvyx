# Evidence receipts and ambiguous delivery

AMC keeps domain lifecycle state authoritative (`thread`, `handoff`, `execution`, and `outbox`).
The evidence receipt is a separate read-only projection that answers a narrower question: which
parts of the end-to-end path are actually proven?

## Five independent legs

```text
capture -> dispatch -> accept -> work -> deliver
```

Each leg is projected independently from canonical events. The receipt is:

- `GREEN` only when every leg is machine/provider proven successful;
- `RED` when a required leg has explicit failure evidence;
- `YELLOW` for incomplete, unknown, or ambiguous evidence.

Evidence provenance is one of `control_plane`, `runtime`, `provider`, `ui`, `user_report`, or
`inferred`. Inferred evidence can explain a result but can never prove success.
An explicit operator/user readback may satisfy a leg as `user_report`, but the aggregate remains
`YELLOW` rather than laundering that assertion into machine-proven `GREEN`.

The projection does not replace lifecycle authority. A heartbeat can prove that a runtime was
observed, but the `work` leg remains pending until an authoritative target-authored terminal;
a provider receipt can prove `deliver` while the canonical thread remains open.

## Runtime outcomes

An identity-bound heartbeat may classify the currently observed runtime state as:

- `progressing`
- `waiting_human`
- `provider_error`
- `runtime_exited`
- `unobservable`

These values are diagnostic evidence. None is a terminal completion event.

## Ambiguous external effects

A provider can apply an effect while the caller loses or cannot parse the native receipt. AMC
records this as `ambiguous_delivery`, not as a retryable failure. The dispatcher never
reclaims or automatically retries that item because doing so could duplicate the effect.

Resolution requires explicit provider readback through `reconcile_ambiguous_delivery`. A delivered
resolution must include the native provider receipt and is appended through the legacy-recognized
`outbox.delivered` envelope; history is never rewritten.
An explicit `not_delivered` result transitions to a resolved dead letter and frees the execution
lineage for a fresh return. The ambiguity fence is emitted through the legacy-recognized
`outbox.dead_lettered` event envelope with `status=ambiguous_delivery`, so rolling back one release
does not silently re-arm the leased send.

## Provenance

The five-leg receipt vocabulary, honest `YELLOW` state, and the rule that unknown evidence is not
success were adapted from Yapitalism by Aytunc Yildizli (MIT):
https://github.com/AytuncYildizli/yapitalism

AMC's implementation is native to its identity-bound append-only event model; no terminal-pane or
voice-client control code is imported.
