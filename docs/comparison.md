# Comparison

This project is closest to agent memory and second-brain systems, but its main
claim is operational governance.

## Adjacent Categories

| Category | Examples | Difference |
| --- | --- | --- |
| Agent frameworks | LangGraph, CrewAI, AutoGen, Mastra | They build agent logic. This project governs agent teams around any harness. |
| Obsidian/wiki memory | Obsidian/MCP wiki projects, Basic Memory, SwarmVault | They emphasize flexible human knowledge. This project keeps markdown/wiki ergonomics but adds governed memory, identity, approvals, and audit. |
| Observability | Langfuse, AgentOps | They observe agent runs. This project controls memory access, writes, approvals, and operational state. |
| MCP transport | mcp-proxy, supergateway, mcp-remote | They bridge protocols. This project uses MCP as one boundary in a broader control plane. |

## Wedge

Wiki-oriented systems are better as a personal, research, or editorial brain:
they are easy to read, link, browse, and reshape.

Arvyx is built to be an institution: current truth over
raw history, a suggest-review-promote write lane, per-agent tokens with
enforced scopes, a hash-chained audit log, and operator governance. Retrieval
is deterministic BM25 with citations by default, with optional hybrid/semantic
modes when an embeddings provider is configured (`docs/retrieval.md`) — and the
control plane is a single-host event log with a warm replica, not a distributed
system; see `docs/multi-machine.md` and `docs/backup-and-health.md` for the
deployment shape and `IMPROVEMENTS.md` for what is still missing.

Retrieval capability claims are reproducible, not asserted. Every
`arvyx benchmark recall --json` result carries a `provenance` block
(`arvyx-benchmark-provenance/v2`) with the committed dataset
(`fixtures/recall-benchmark.json`, SHA-256
`5829d9c26908721f000071274bc206e574274da5ba9126d748b1b3fa6efb3817`), the indexed corpus manifest,
retrieval/index/embedding configuration, and implementation version and source
hash. The deterministic run ID binds all of those inputs. A comparison or
release claim must cite that run ID and dataset/corpus hashes; without them the
claim has no committed artifact behind it.

## Obsidian-Oriented Structures

Arvyx is intentionally compatible with Obsidian-style vaults, but it does not
treat a wiki as the whole control model.

| Concern | Wiki-oriented vault | Arvyx governed vault |
| --- | --- | --- |
| Human editing | Excellent. Markdown, backlinks, and folders are natural for operators. | Preserved. Curated docs remain markdown with frontmatter and wikilinks. |
| Agent authority | Usually implicit in note placement and naming conventions. | Explicit through project lanes, registry identity, write policy, and tool profiles. |
| Recall proof | A search result may link to a note, but the citation and excerpt contract varies. | Recall returns compact answers, memory cards, exact excerpts, and source paths. |
| Raw history | Chat logs and scratch notes can become adjacent to canonical knowledge. | Raw/imported/archive lanes are separated from curated recall by default. |
| Approvals | Usually represented as text or task state. | Single-use approval hashes bind permission to exact command text. |
| Release readiness | Manual review can work, but it is hard to reproduce. | Doctor, audit, dogfood, evidence export, and release-candidate checks are executable. |

The practical position is simple: use Obsidian-friendly markdown for the human
layer, then put Arvyx's governance layer around it before autonomous agents rely
on it. That is the superiority claim. Not prettier notes; safer operational
memory.
