# Notifier adapters

Authority prerequisite: set `ARVYX_VAULT` to the actual configured absolute vault path before using these commands (for the maintained V2 host units, `/srv/arvyx-v2/data/vault`). Do not derive it from `--state`; state may be outside the vault. An empty variable is not a valid configuration. Global `--authority-vault` precedes the CLI subcommand; the standalone dispatcher uses `--vault`.


`arvyx health notify-check` computes notification and escalation candidates
for pending War Room threads (see the health handoff docs), then hands them to
exactly one delivery adapter. The candidate/dedupe logic is adapter-agnostic:
dedupe state is projected from `thread.notification_sent` events in the same
append-only control log, so switching adapters never re-notifies.

## Adapters

| Adapter    | What it does                                   | Requires                                          |
| ---------- | ---------------------------------------------- | ------------------------------------------------- |
| `stdout`   | Prints notification text. Always safe. Default. | nothing                                           |
| `file`     | Appends a JSONL delivery row per notification.  | `--deliveries PATH`                               |
| `webhook`  | POSTs a JSON payload to a generic target.       | `--webhook-url-env NAME` (env var holds the URL)  |
| `telegram` | Sends via the Telegram Bot API.                 | `--config` + two env vars (token and chat id)     |

```bash
arvyx --authority-vault "$ARVYX_VAULT" health notify-check --state tmp/events.jsonl --adapter stdout --json
arvyx --authority-vault "$ARVYX_VAULT" health notify-check --state tmp/events.jsonl --adapter file --deliveries tmp/deliveries.jsonl --json
arvyx --authority-vault "$ARVYX_VAULT" health notify-check --state tmp/events.jsonl --adapter webhook --webhook-url-env ARVYX_NOTIFY_WEBHOOK --json
arvyx --authority-vault "$ARVYX_VAULT" health notify-check --state tmp/events.jsonl --adapter telegram --config examples/notifiers/telegram.example.json --json
```

## Safety model

- **Safe default.** The default adapter is `stdout`; nothing leaves the
  machine unless an operator explicitly selects an outbound adapter.
- **Credentials live in the environment, never in configs or flags.** The
  telegram config names the env vars (`bot_token_env`, `chat_id_env`); the
  webhook URL comes from the env var named by `--webhook-url-env`. The
  adapter refuses to run when they are unset.
- **Fail before claiming.** Adapter configuration is validated before
  candidates are computed, so a misconfigured adapter aborts without writing
  dedupe events — the next correctly configured run still notifies.
- **Attempt claim and explicit delivery outcome.** Candidate claims are appended atomically under the state lock before delivery. Definite local refusal or HTTP rejection reports `failed` and appends `thread.notification_failed`, releasing that kind's claim for retry. Once transport may have consumed the POST, disconnect, timeout, body-limit or framing failure reports `ambiguous` and retains the claim; the CLI reports a nonzero result. Provider readback is required before interpreting uncertainty as non-delivery. Normal claims still expire after the configured dedupe window (default 240 minutes), when another send can occur; escalation is a separate kind whose retained claim does not expire. This remains an interim at-least-once notifier without durable provider reconciliation or an exactly-once guarantee.
- **No secrets in deliveries.** Notification title/text/detail pass through
  secret-shape redaction, and the telegram bot token is scrubbed from any
  failure detail.
- **The telegram adapter only talks to the real Telegram API.** The bot token
  rides in the request URL, so a config pointing `api_base_url` at another
  host would hand the token to that host. Any value other than
  `https://api.telegram.org` is refused. Local fixture testing requires BOTH
  `ARVYX_ALLOW_TELEGRAM_TEST_API_BASE=1` and a test-shaped token
  (`<digits>:TEST...`), so the override can never fire with real credentials.
- **The webhook target is trusted operator configuration.** The URL comes
  from an environment variable the operator sets; the product validates the
  scheme but deliberately does not second-guess the destination. Do not point
  it at URLs derived from untrusted input.
- **Configs are adapter-checked.** A config whose `adapter` field names a
  different adapter than the one selected fails clearly instead of being
  half-read.
- **Dashboard links are validated before message construction.** A
  `--dashboard-url` must be http(s), free of whitespace/control characters,
  embedded credentials, and secret-shaped query strings. Loopback links
  (`127.0.0.1`, `localhost`) are allowed only on the local `stdout`/`file`
  adapters — an outbound adapter with a loopback link is refused rather than
  sending a link nobody can open.
- **`--dry-run` does nothing twice over:** no dedupe events are written and
  no adapter side effect happens; every delivery is reported as `dry-run`.

## Ambiguous delivery and reconciliation

`ambiguous` is not evidence of non-delivery. The notifier validates URL,
credentials-in-URL, port and bounded timeout before transport entry; those
local refusals are `failed`. An explicit HTTP rejection is also `failed`.
Once the shared opener is entered, it provides no send-phase receipt, so even
DNS/connect errors reported as `URLError` are conservatively `ambiguous`.
Disconnects, body-read deadlines, incomplete/framing-invalid responses and
oversized successful response bodies retain the same claim. Diagnostic details
name the exception class rather than copying transport URLs or response bodies.

An ambiguous result does not append `thread.notification_failed`. The existing
`thread.notification_sent` event is an **attempt claim**, not proof of provider
acceptance; the delivery result must be retained separately by the operator.
The claim is shared across adapters and suppresses that kind, not every possible
message: an independently due escalation can still send.

Before normal-claim expiry (default 240 minutes from claim creation, not from
response completion), pause scheduled notification sending for the affected
state if duplicate delivery is unacceptable. Inspect the provider's own history
and correlate thread, destination, message text and attempt time. Keep accepted
or inconclusive attempts claimed; do not manufacture failure receipts or remove
log events merely to retry. There is no durable notifier reconciliation command
or provider idempotency key here. A verified non-delivery or operator-approved
resend therefore requires an explicit operational decision; this lane adds no
automatic release mechanism for ambiguity. An escalation claim has no automatic
expiry, so an uncertain escalation may remain suppressed indefinitely.

Expiry does **not** establish non-delivery: the next normal notification can
duplicate an earlier accepted POST. A slow in-flight attempt can also outlive
its dedupe window. Local stdout/file failures still release claims for retry;
a partial local write can therefore duplicate output. The interim at-least-once
retry model neither guarantees eventual delivery after an ambiguous escalation
nor provides exactly-once delivery. Durable provider reconciliation remains
separate work; ambiguity retention only fences immediate blind resend.

## Telegram example

`examples/notifiers/telegram.example.json` uses placeholders and env var
names only:

```json
{
  "adapter": "telegram",
  "api_base_url": "https://api.telegram.org",
  "bot_token_env": "ARVYX_TELEGRAM_BOT_TOKEN",
  "chat_id_env": "ARVYX_TELEGRAM_CHAT_ID"
}
```

`api_base_url` exists so tests and local fixtures can point the adapter at a
loopback fake server, but it is gated: production refuses any base other
than `https://api.telegram.org`, and the test override requires the explicit
`ARVYX_ALLOW_TELEGRAM_TEST_API_BASE=1` env gate plus an obviously fake
`<digits>:TEST...` token. No test or default path ever performs a real send.

## Claim generations (source-only ledger boundary repair)

The delivery entry point now claims candidates and captures each actual control
event ID under one state lock. Each failure carries `claim_event_id`. Its writer
compares that ID with the latest thread/kind claim under the same lock before
appending a failure event. An old sender's late rejection therefore cannot release
a replacement sender's dedupe claim. Same-generation definite failures remain
retryable; ambiguous acceptance retains the claim. No network I/O holds the lock.

All notification sweeps now use `health_ops.notify_check`, which captures the
actual appended event ID in each non-dry candidate under the state lock. The
notifier re-exports the single `control.record_thread_notification_failure`
writer; its keyword-only `claim_event_id` is mandatory. All actual package and
script call sites, including the watchdog regression, supply the original ID.
Projection ignores generationless or stale historical failure events rather than
letting them release another claim. Historical bytes are not rewritten; this
conservative policy may retain old claims until normal expiry (or indefinitely
for escalation). A same-generation failure still permits retry. No authority,
notification-kind, ambiguity, retirement, archive, or exact-event fence is relaxed.
Regression sources were updated/added but not executed; release remains HOLD.
