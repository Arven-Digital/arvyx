# Importers

Importers bring external markdown memory into governed project lanes without
making loose notes authoritative by default.

The core importer is intentionally small:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli import markdown \
  ./notes \
  --vault fixtures/synthetic-vault \
  --project demo-agent \
  --json
```

It accepts a single markdown file or a directory tree of markdown files.
Use `--dry-run` to preview planned writes without creating files:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli import markdown \
  ./notes \
  --vault fixtures/synthetic-vault \
  --project demo-agent \
  --dry-run \
  --json
```

There are also compatibility front doors for common agent-memory vault shapes:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli import obsidian \
  ./obsidian-vault \
  --vault fixtures/synthetic-vault \
  --project demo-agent \
  --json

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli import basic-memory \
  ./basic-memory-export \
  --vault fixtures/synthetic-vault \
  --project demo-agent \
  --json
```

Imported files are written under:

```text
projects/<project>/imported/
projects/<project>/imported/obsidian/
projects/<project>/imported/basic-memory/
```

Project ids are validated before path construction. Valid ids are lowercase
slugs such as `demo-agent`, `agent_1`, or `project123`; traversal-shaped values
such as `../../outside` are rejected before any import or recall path is used.

Each import lane also receives an append-only manifest:

```text
projects/<project>/imported/import-manifest.jsonl
projects/<project>/imported/obsidian/import-manifest.jsonl
projects/<project>/imported/basic-memory/import-manifest.jsonl
```

The manifest records source type, imported paths, skipped paths, counts, and a
timestamp. It intentionally does not record absolute local source paths.

That lane is recallable, cited, and visible to `doctor`, but it is separate from
current-truth files such as `STATUS.md`, `DECISIONS.md`, and `RUNBOOK.md`.

## Safety Rules

- secret-shaped notes are skipped before writing
- dry runs report planned paths without writing files
- dry runs do not write manifest events
- successful imports append an import manifest event
- duplicate filenames are disambiguated as `note.md`, `note-2.md`, and so on
- project ids cannot escape `projects/<project>/`
- imported notes receive frontmatter when missing
- existing frontmatter is preserved
- Obsidian imports receive `imported` and `obsidian` tags when frontmatter is missing
- Basic Memory imports receive `imported` and `basic-memory` tags when frontmatter is missing
- raw and archive lanes remain excluded from recall
- imports are not promoted into current truth automatically

Source preflight captures immutable in-memory bytes before the mutation lock:
at most 10,000 enumerated entries, 256 Markdown files, 1 MiB per file and
16 MiB total, with directory depth capped at 32. Reads use nonblocking no-follow
regular-file descriptors. Rejected source names are not echoed into receipts.
Destination enumeration is capped at 10,000 entries and each filename gets at
most 1,024 collision candidates. Exceeding a budget refuses the invocation;
there is no promise of unlimited imports or wall-clock bounded filesystem I/O.
Source preflight refusal occurs before destination mutation. A later disk or
manifest failure can still leave already published notes; import is not an
all-files atomic transaction.

This gives teams a path from Obsidian, Basic Memory, or plain markdown vaults
into Arvyx without pretending that imported notes are already reviewed facts.


## Stored bytes and native context provenance

Markdown import preflights the fully rendered UTF-8 document, including wrapper and
metadata, against the same 1,048,576-byte bound used by lifecycle readers. Oversize
refusal precedes publication, including dry runs and whole-batch preflight.

Native transcript import persists only versioned bounded delimiter state, with
capture rows, the conversation context and cursor provenance committed atomically.
Old four-element contexts can have lost Unicode uncertainty even when their state
looks closed/False. They are quarantined, with no cursor advance, history deletion
or silent trust upgrade. The private owner inspection/reconciliation flow verifies
an exact current digest and reimports from zero into a new event namespace, retaining
old archive rows and charged quarantined context. New conversation selection uses
versioned cursor provenance; an unknown legacy session cursor is not adopted.
No real retained archive is inspected or rewritten by the pass-5 tests.

Markdown link publication now records a durable exact inode/hash/target/stage
witness before linking. A governed mutation reconciles only that witnessed
publication under the canonical vault lock, repeats its namespace barrier and
retires the extra stage link. Orphan or foreign stages are never adopted.
Coordinated composition capture runs canonical import/promotion recovery before
inventory. It materializes completed exact receipt-bound forget archive/witness
pairs as independent files; unfinished/foreign links refuse. The public export
reader still requires singly linked regular files.

Retrieval reads eligible Markdown through bounded nonblocking no-follow file
descriptors and checks identity again. FIFOs, devices, symlinks, extra links and
oversized/changed files are refused before a blocking content read.
