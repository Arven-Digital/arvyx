# Structured memory suggestion quality

`memory.suggest_batch` is the strict, extraction-oriented write boundary. The legacy `memory.suggest` contract remains unchanged for compatibility.

Every batch item must include these admission fields:

| Field | Values | Rule |
| --- | --- | --- |
| `memory_class` | `static`, `dynamic` | `static` is valid only with `content_class: durable_identity`. Preferences, plans, state, and inferences must be `dynamic`. |
| `content_class` | `durable_identity`, `durable_fact`, `preference`, `plan`, `state`, `inferred`, `assistant_suggestion`, `research_quote`, or a rejected class below | Drives deterministic admission; the server does not scan prose for banned phrases. `research_quote` may contain quoted prompt-injection text and is not rejected as `PROMPT_INJECTION` when the other admission rules pass. |
| `future_job` | non-empty string | Names a concrete downstream use for the memory. |
| `assistant_suggestion_accepted` | boolean | Must be `true` when `content_class` is `assistant_suggestion`. |

The complete closed schema is exposed by the MCP `memory.suggest_batch` tool and by `GET /schemas/memory-suggest-batch`. The HTTP schema route intentionally requires `memory.suggest`, matching the capability needed to use the contract; it is not public discovery metadata. Unknown or missing fields reject the entire batch before any pending file is published.

## Rejection reason codes

- `NOISE_BOILERPLATE`
- `NOISE_GREETING`
- `PROMPT_INJECTION`
- `ASSISTANT_SUGGESTION_UNACCEPTED`
- `NO_FUTURE_JOB`
- `STATIC_REQUIRES_DURABLE_IDENTITY`
- `INVALID_CONTENT_CLASS`
- `INVALID_MEMORY_CLASS`
- `QUALITY_METADATA_REQUIRED`

Accepted pending files persist `memory_class`, `content_class`, `future_job`, `assistant_suggestion_accepted`, and `admission_reason: FUTURE_JOB_ACCEPTED` as JSON-escaped frontmatter values. Classification is explicit metadata rather than naive text censorship: for example, legitimate research may quote prompt-injection language under `content_class: research_quote` when it has a concrete future job.

## Example

```json
{
  "project": "demo-agent",
  "author": "demobot",
  "memories": [
    {
      "title": "Relay owner",
      "content": "Atlas owns relay access review.",
      "tags": ["identity"],
      "content_class": "durable_identity",
      "memory_class": "static",
      "future_job": "Identify the accountable owner during access review.",
      "assistant_suggestion_accepted": false
    }
  ]
}
```
