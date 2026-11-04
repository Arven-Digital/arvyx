# Changelog

All notable changes to Arvyx are documented here. Versions follow semantic
versioning where practical during alpha; incompatible changes may still occur
before 1.0 and are called out explicitly.

## 0.1.0a1

Second public alpha. The control plane now runs on Windows and macOS, and the
Windows path walk accepts the extended-length prefix that `Path.resolve()`
returns, so a resolved name is no longer refused as a UNC root.

- Windows: NTFS owner and DACL privacy model, descriptor-relative opens that
  never follow reparse points, a loopback owner endpoint and a Windows CI lane
  including the npm package smoke.
- macOS: the control plane runs without Linux-only calls, Darwin files are
  classified for release and the on-machine darwin-arm64 native binary is
  admitted.
- The no-follow root walk drops the Windows extended-length path prefix before
  parsing, the same rule the containment check uses, and still refuses real UNC
  roots.
- Dependency bumps reviewed together: pytest, cyclonedx-bom, pip-licenses and
  actions/setup-node.

## 0.1.0a0 (first public candidate)

Initial public release candidate of the self-hosted memory and control plane:

- governed markdown memory with a reviewed write lane and cited, token-bounded recall;
- scoped agent, runtime, machine and project identities with per-agent bearer tokens;
- append-only tasks, approvals bound to exact command hashes, handoffs, War Room
  threads, health handoffs and a hash-chained audit log, projected into SQLite;
- MCP over stdio and HTTP, the scoped `safe-mcp-bridge`, the `arvyx` CLI and the
  packaged operator dashboard;
- the control room: bounded harness discovery, explicit identity registration,
  read-only session-metadata adapters for Hermes, Claude Code and Codex, Last 5 /
  All with search and pagination, reviewed workspace preparation, optional pairing;
- a reproducibly built, digest-pinned native terminal frontend for Linux x86_64;
- the `arvyx` npm package bundling the Python wheel and the web control room;
- executable release gates: audit, readiness, recall benchmarks, self-dogfood,
  Docker runtime smoke, real MCP-client evidence and multi-model review receipts.
