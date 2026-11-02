# Self Dogfood

`arvyx dogfood self` runs the product against this repository's own public-safe
docs.

It creates a temporary synthetic vault and imports only explicitly public-approved
or clean-room documentation listed in `config/public-release-paths.json`.
Private-only, unclassified, and privacy-noticed documents are excluded before
import; the manifest must be valid, and source symlinks are refused. A temporary
snapshot is used for import. This is not permission to export the repository.
Recall/context-pack checks use public retrieval documentation, not the private
release-gate document. Evidence's hybrid comparison disables network embeddings
explicitly and records that policy in provenance; it does not qualify a hosted
embedding model. Optional Docker/bridge checks remain separately opt-in.

## Run

```bash
arvyx dogfood self --json
arvyx dogfood self --run-docker --mcp-client-evidence tmp/mcp-client-evidence.json --json
```

## Checks

- initialize a governed demo vault
- import this repo's docs through the markdown importer
- write importer manifest events
- recall the public retrieval contract
- build a context pack from the imported public docs
- run the normal demo after self-import
- export release evidence from the dogfood vault
- optionally include release-host Docker and real MCP client evidence

## Why It Matters

This proves Arvyx Memory & Control can ingest and reason over its own product
documentation without relying only on handcrafted synthetic answers.
