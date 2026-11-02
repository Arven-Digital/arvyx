.PHONY: dev-install test test-python test-frontend test-npm npm-package-smoke frontend-deps check-node contract-check build dependency-audit sbom license-check demo doctor mcp-smoke mcp-client-smoke mcp-client-evidence-smoke mcp-client-evidence-generate-smoke mcp-streaming-smoke mcp-control-smoke thread-smoke health-smoke notify-smoke store-smoke api-smoke live-api-smoke auth-smoke import-smoke bridge-smoke bridge-lint-smoke bridge-e2e-smoke bridge-dogfood-smoke self-dogfood-smoke readiness-smoke audit-smoke benchmark-smoke evidence-smoke release-candidate-smoke release-candidate-e2e-smoke release-host-schema-smoke package-smoke docker-compose-smoke docker-runtime-smoke projection-benchmark synthetic-restore-drill docker-demo scan release-scan release-boundary ci

projection-benchmark:
	$(PYTHON) scripts/projection_checkpoint_benchmark.py --json

synthetic-restore-drill:
	$(PYTHON) scripts/synthetic_backup_restore_drill.py --json

PYTEST_ARGS ?=
PYTHON ?= python3
# Recipes that cd into a temporary directory must still find the configured
# denylist: resolve it against the directory make was started from.
ifneq ($(strip $(ARVYX_PRIVATE_DENYLIST)),)
override export ARVYX_PRIVATE_DENYLIST := $(abspath $(ARVYX_PRIVATE_DENYLIST))
endif
PYTHONPATH_SEP ?= $(if $(findstring Windows_NT,$(OS)),;,:)
EXE_SUFFIX ?= $(if $(findstring Windows_NT,$(OS)),.exe,)
PYTHONPATH := packages/arvctl/src$(PYTHONPATH_SEP)packages/safe-mcp-bridge/src$(PYTHONPATH_SEP)apps/control-center-api/src
VAULT ?= fixtures/synthetic-vault
DEV_LOCK ?= requirements/dev.lock
EVIDENCE_CLIENT_LOCK ?= requirements/mcp-client.lock
SECRET_EDGE_LOCK ?= requirements/secret-edge.lock
DIST_DIR ?= dist
SBOM_PATH ?= $(DIST_DIR)/environment.sbom.cdx.json

dev-install:
	$(PYTHON) -m pip install --require-hashes -r $(DEV_LOCK) -r $(SECRET_EDGE_LOCK)
	$(PYTHON) -m pip install --no-deps --no-build-isolation -e .

build:
	rm -rf $(DIST_DIR)
	$(PYTHON) -m build --no-isolation --outdir $(DIST_DIR)

dependency-audit:
	$(PYTHON) -m pip_audit -r $(DEV_LOCK) --strict --disable-pip --progress-spinner off
	$(PYTHON) -m pip_audit -r $(EVIDENCE_CLIENT_LOCK) --strict --disable-pip --progress-spinner off
	$(PYTHON) -m pip_audit -r $(SECRET_EDGE_LOCK) --strict --disable-pip --progress-spinner off

sbom:
	mkdir -p $(dir $(SBOM_PATH))
	$(PYTHON) -m cyclonedx_py environment --pyproject pyproject.toml --output-reproducible --output-file $(SBOM_PATH)
	$(PYTHON) -c 'import json; from pathlib import Path; p=Path("$(SBOM_PATH)"); d=json.loads(p.read_text(encoding="utf-8")); assert d.get("bomFormat") == "CycloneDX" and d.get("specVersion") and d.get("components")'

license-check:
	$(PYTHON) scripts/license_notice_check.py
	$(PYTHON) scripts/license_notice_check.py --secret-edge

secret-edge-install:
	$(PYTHON) -m pip install --require-hashes -r $(SECRET_EDGE_LOCK)

secret-edge-license-check:
	$(PYTHON) scripts/license_notice_check.py --secret-edge

# pytest collects module functions AND unittest.TestCase classes; one coverage run.
test: test-python test-frontend test-npm

# Parallel workers (pytest-xdist, one file per worker so module-level fixtures stay
# together); pytest-cov merges the workers' data into COVERAGE_FILE.
PYTEST_WORKERS ?= auto
test-python:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m coverage erase
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m pytest packages/arvctl/tests tests -q -n $(PYTEST_WORKERS) --dist loadfile --cov --cov-branch $(PYTEST_ARGS)

check-node:
	node -e 'const [a,b]=process.versions.node.split(".").map(Number); if(a<24||(a===24&&b<11)){console.error("Node >=24.11 required for supported frontend/npm acceptance");process.exit(2)}'

frontend-deps: check-node
	npm --prefix frontends/paperclip ci --ignore-scripts --no-audit --no-fund

test-frontend: check-node
	npm --prefix frontends/paperclip test

test-npm: check-node
	npm --prefix packaging/npm test

# Builds the local npm tarball (offline, from the locked frontend cache), installs it
# into empty prefixes and exercises setup/doctor/amc plus fail-closed negative controls.
npm-package-smoke: check-node
	$(PYTHON) scripts/npm_package_smoke.py --json

contract-check:
	$(PYTHON) scripts/generate_external_contracts.py --check

demo:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli demo --vault $(VAULT) --json

doctor:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli doctor --vault $(VAULT) --json

mcp-smoke:
	printf '%s\n' '{"jsonrpc":"2.0","id":"make","method":"tools/call","params":{"name":"memory.recall","arguments":{"question":"what did we decide about safe mcp bridge","project":"demo-agent","max_tokens":120}}}' \
		| PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli mcp --vault $(VAULT)

mcp-client-smoke:
	$(PYTHON) scripts/mcp_client_examples_check.py --json | grep -q '"ok": true'

mcp-client-evidence-smoke:
	$(PYTHON) scripts/mcp_client_evidence_check.py --json | grep -q '"ok": true'

mcp-client-evidence-generate-smoke:
	$(eval TMPDIR := $(shell mktemp -d))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli evidence mcp-client --output $(TMPDIR)/mcp-client-evidence.json --json \
		| grep -q '"ok": true'
	$(PYTHON) scripts/mcp_client_evidence_check.py $(TMPDIR)/mcp-client-evidence.json --json \
		| grep -q '"ok": true'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli release-host \
		--mcp-client-evidence $(TMPDIR)/mcp-client-evidence.json \
		--json \
		| grep -Fq "client is arvyx's own self client; external evidence is required"

mcp-streaming-smoke:
	$(PYTHON) scripts/mcp_streaming_compat_check.py --json | grep -q '"ok": true'

mcp-control-smoke:
	$(eval STATE := $(shell mktemp))
	printf '%s\n' '{"jsonrpc":"2.0","id":"make-control","method":"tools/call","params":{"name":"control.task_create","arguments":{"title":"Review MCP control smoke","owner":"vesper"}}}' \
		| PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli mcp --vault $(VAULT) --state $(STATE) --profile operator
	printf '%s\n' '{"jsonrpc":"2.0","id":"make-control-list","method":"tools/call","params":{"name":"control.task_list","arguments":{}}}' \
		| PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli mcp --vault $(VAULT) --state $(STATE) --profile operator
	printf '%s\n' '{"jsonrpc":"2.0","id":"make-handoff","method":"tools/call","params":{"name":"control.handoff_create","arguments":{"title":"Review MCP handoff control","from_agent":"vesper","to_agent":"operator"}}}' \
		| PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli mcp --vault $(VAULT) --state $(STATE) --profile operator
	printf '%s\n' '{"jsonrpc":"2.0","id":"make-bus","method":"tools/call","params":{"name":"control.bus_post","arguments":{"message":"Review MCP bus control","channel":"ops","actor":"vesper"}}}' \
		| PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli mcp --vault $(VAULT) --state $(STATE) --profile operator

thread-smoke:
	$(eval STATE := $(shell mktemp))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" thread post --actor operator --to vesper --channel demo-agent --type ask \
		--title "Review thread smoke" --text "Synthetic thread smoke." --state $(STATE) --json \
		| grep -q '"status": "open"'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" thread post --actor operator --to vesper --channel demo-agent --type status \
		--title "Thread smoke status" --state $(STATE) --json \
		| grep -q '"pending": false'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" thread pending vesper --state $(STATE) --json \
		| grep -q 'Review thread smoke'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" thread read-all vesper --state $(STATE) --json \
		| grep -q 'Thread smoke status'

health-smoke:
	$(eval STATE := $(shell mktemp))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" health daily-handoff --config examples/local-dev/daily-handoff.example.json --date 2026-01-01 --state $(STATE) --json \
		| grep -q '"skipped": \[\]'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" health daily-handoff --config examples/local-dev/daily-handoff.example.json --date 2026-01-01 --state $(STATE) --json \
		| grep -q '"created": \[\]'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" health agent-matrix \
		--config examples/local-dev/agents.json --timeout 1 --json \
		| grep -q '"status": "SKIP"'

notify-smoke:
	$(eval STATE := $(shell mktemp))
	$(eval DELIVERIES := $(shell mktemp))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" health daily-handoff --config examples/local-dev/daily-handoff.example.json --date 2026-01-01 --state $(STATE) --json >/dev/null
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" health notify-check --state $(STATE) --dry-run --json \
		| grep -q '"dry_run": true'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" health notify-check --state $(STATE) \
		--adapter file --deliveries $(DELIVERIES) --json \
		| grep -q '"status": "recorded"'
	grep -q '"adapter": "file"' $(DELIVERIES)
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" health notify-check --state $(STATE) --json \
		| grep -q '"candidates": \[\]'

store-smoke:
	$(eval STATE := $(shell mktemp))
	$(eval DB := $(shell mktemp))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" task create "Review store smoke" --owner vesper --state $(STATE) --json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" handoff create "Review handoff smoke" --from operator --to vesper --state $(STATE) --json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" bus post "Review bus smoke" --actor operator --state $(STATE) --json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" store sync --state $(STATE) --db $(DB) --retain-events 2 --json \
		| grep -q '"retention": "sqlite-events:last-2"'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" store sync --state $(STATE) --db $(DB) --retain-events 2 --json \
		| grep -q '"retention": "sqlite-events:last-2"'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" store manifest --state $(STATE) --json \
		| grep -q '"retention": "append-only-jsonl"'

api-smoke:
	$(eval STATE := $(shell mktemp))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" api-call GET /health --state $(STATE)
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" api-call POST /memory/recall \
		--state $(STATE) \
		--body '{"question":"which guardrail proxy protects credentials","project":"demo-agent","max_tokens":120}'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" api-call POST /mcp \
		--state $(STATE) \
		--body '{"jsonrpc":"2.0","id":"api-mcp","method":"tools/list"}' \
		| grep -q 'memory.recall'

live-api-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli dogfood live-api --json

auth-smoke:
	$(eval STATE := $(shell mktemp))
	$(eval AUTHDIR := $(shell mktemp -d))
	$(PYTHON) scripts/create_secret_file.py $(AUTHDIR)/control-secret
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli --authority-vault "$(VAULT)" api-call POST /memory/recall \
		--state $(STATE) \
		--auth-file $(AUTHDIR)/control-secret \
		--body '{"question":"which guardrail proxy protects credentials","project":"demo-agent","max_tokens":120}'
	rm -rf $(AUTHDIR)

import-smoke:
	$(eval TMPDIR := $(shell mktemp -d))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli init $(TMPDIR)/vault --json
	printf '%s\n' 'Imported note: the command center keeps markdown imports behind governed project lanes.' > $(TMPDIR)/note.md
	mkdir -p $(TMPDIR)/obsidian $(TMPDIR)/basic-memory
	printf '%s\n' 'Obsidian import: linked notes remain in a governed imported lane.' > $(TMPDIR)/obsidian/wiki-note.md
	printf '%s\n' 'Basic Memory import: exported memory stays separate from current truth.' > $(TMPDIR)/basic-memory/memory-note.md
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli import markdown $(TMPDIR)/note.md \
		--vault $(TMPDIR)/vault \
		--project demo-agent \
		--json \
		| grep -q '"manifest_path": "projects/demo-agent/imported/import-manifest.jsonl"'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli import markdown $(TMPDIR)/note.md \
		--vault $(TMPDIR)/vault \
		--project demo-agent \
		--dry-run \
		--json \
		| grep -q '"dry_run": true'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli import obsidian $(TMPDIR)/obsidian \
		--vault $(TMPDIR)/vault \
		--project demo-agent \
		--json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli import basic-memory $(TMPDIR)/basic-memory \
		--vault $(TMPDIR)/vault \
		--project demo-agent \
		--json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli recall \
		"governed imported lane current truth" \
		--vault $(TMPDIR)/vault \
		--project demo-agent \
		--json

bridge-smoke:
	$(eval TMPDIR := $(shell mktemp -d))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli bridge-policy --profile read-only --json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli bridge-policy --profile operator --output $(TMPDIR)/operator.json --json
	grep -q 'control.approval_consume' $(TMPDIR)/operator.json
	grep -q '"mode": "allowlist"' $(TMPDIR)/operator.json

bridge-lint-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m safe_mcp_bridge.cli lint examples/safe-mcp-bridge/read-only.json --json \
		| grep -q '"ok": true'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m safe_mcp_bridge.cli lint examples/safe-mcp-bridge/operator.json --json \
		| grep -q '"ok": true'

bridge-e2e-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) scripts/bridge_e2e_fixture_check.py --json

bridge-dogfood-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) scripts/bridge_dogfood_smoke.py --json

self-dogfood-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli dogfood self --json

readiness-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli readiness --json

audit-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli audit --json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli audit --json | grep -q '"ok": true'

benchmark-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli benchmark recall --json
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli benchmark recall --retrieval-mode hybrid --json \
		| grep -q '"retrieval_mode": "hybrid"'

evidence-smoke:
	$(eval TMPDIR := $(shell mktemp -d))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli evidence mcp-client --output $(TMPDIR)/mcp-client-evidence.json --json \
		| grep -q '"ok": true'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli evidence export --output $(TMPDIR)/evidence.json --json \
		| grep -q '"release_blockers"'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli evidence export \
		--output $(TMPDIR)/evidence-with-mcp.json \
		--mcp-client-evidence $(TMPDIR)/mcp-client-evidence.json \
		--json \
		| grep -Fq "client is arvyx's own self client; external evidence is required"
	test -s $(TMPDIR)/evidence.json

release-candidate-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli release-candidate --json \
		| grep -q '"private_preview_allowed": true'
	$(eval TMPDIR := $(shell mktemp -d))
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli evidence mcp-client --output $(TMPDIR)/mcp-client-evidence.json --json \
		| grep -q '"ok": true'
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli release-candidate \
		--mcp-client-evidence $(TMPDIR)/mcp-client-evidence.json \
		--json \
		| grep -Fq "client is arvyx's own self client; external evidence is required"

release-candidate-e2e-smoke:
	PYTHONPATH="$(PYTHONPATH)" $(PYTHON) scripts/release_candidate_e2e_check.py --json \
		| grep -q '"ok": true'

release-host-schema-smoke:
	$(eval TMPDIR := $(shell mktemp -d))
	@set +e; PYTHONPATH="$(PYTHONPATH)" $(PYTHON) -m arvyx_control.cli release-host --json > $(TMPDIR)/release-host.json; rc=$$?; set -e; \
		test $$rc -ne 0; \
		$(PYTHON) -c 'import json; d=json.load(open("$(TMPDIR)/release-host.json", encoding="utf-8")); assert d["public_release_ready"] is False and d["blockers"]'

package-smoke:
	$(eval TMPDIR := $(shell mktemp -d))
	$(PYTHON) -m venv $(TMPDIR)/venv
	$(eval VENV_BIN := $(if $(findstring Windows_NT,$(OS)),$(TMPDIR)/venv/Scripts,$(TMPDIR)/venv/bin))
	$(VENV_BIN)/python$(EXE_SUFFIX) -m pip install --require-hashes -r $(DEV_LOCK) --quiet
	$(VENV_BIN)/python$(EXE_SUFFIX) -m pip wheel . --no-deps --no-build-isolation --wheel-dir $(TMPDIR)/dist --quiet
	$(VENV_BIN)/python$(EXE_SUFFIX) -m pip install --no-deps $(TMPDIR)/dist/*.whl --quiet
	$(VENV_BIN)/arvyx$(EXE_SUFFIX) --help
	$(VENV_BIN)/safe-mcp-bridge$(EXE_SUFFIX) --help
	cd $(TMPDIR) && $(VENV_BIN)/python$(EXE_SUFFIX) -m arvyx_control_center_api --help
	cd $(TMPDIR) && $(VENV_BIN)/arvyx$(EXE_SUFFIX) demo --json | grep -q '"ok": true'
	cd $(TMPDIR) && $(VENV_BIN)/arvyx$(EXE_SUFFIX) benchmark recall --json | grep -q '"score": 100'
	cd $(TMPDIR) && if $(VENV_BIN)/arvyx$(EXE_SUFFIX) release-candidate --json 2> $(TMPDIR)/release-candidate.err; then exit 1; fi
	grep -q -- '--repo must point at an arvyx checkout' $(TMPDIR)/release-candidate.err
	cd $(TMPDIR) && $(VENV_BIN)/arvyx$(EXE_SUFFIX) dogfood self --repo $(CURDIR) --json
	cd $(TMPDIR) && $(VENV_BIN)/arvyx$(EXE_SUFFIX) dogfood live-api --vault $(CURDIR)/$(VAULT) --json
	cd $(TMPDIR) && $(VENV_BIN)/arvyx$(EXE_SUFFIX) evidence mcp-client --vault $(CURDIR)/$(VAULT) --output $(TMPDIR)/mcp-client-evidence.json --json | grep -q '"ok": true'
	cd $(TMPDIR) && $(VENV_BIN)/arvyx$(EXE_SUFFIX) release-candidate --repo $(CURDIR) --vault $(CURDIR)/$(VAULT) --benchmark-cases $(CURDIR)/fixtures/recall-benchmark.json --json | grep -q '"private_preview_allowed": true'
	$(VENV_BIN)/arvyx$(EXE_SUFFIX) --authority-vault "$(abspath $(VAULT))" api-call GET /dashboard --state $(TMPDIR)/events.jsonl | grep -q 'Arvyx Control Plane'

docker-compose-smoke:
	$(PYTHON) scripts/docker_compose_check.py --json | grep -q '"ok": true'

docker-runtime-smoke:
	$(PYTHON) scripts/docker_runtime_smoke.py --json | grep -q '"ok": true'

scan: release-scan

# Explicit reduced diagnostic only; never an aggregate/release prerequisite.
.PHONY: scan-shapes
scan-shapes:
	$(PYTHON) scripts/private_context_scan.py --shapes-only

release-scan:
	$(PYTHON) scripts/private_context_scan.py

release-boundary:
	$(PYTHON) scripts/public_release_boundary.py

docker-demo:
	docker build -t arvyx:demo .
	docker run --rm arvyx:demo

.PHONY: ci-preflight ci-integration
# Disjoint groups: hosted CI runs each once; local ci retains every prerequisite.
ci-preflight: contract-check mcp-smoke mcp-client-smoke mcp-client-evidence-smoke mcp-client-evidence-generate-smoke mcp-streaming-smoke release-host-schema-smoke docker-compose-smoke

# The integration smokes are independent processes (own temp dirs, ephemeral ports),
# so they run under a parallel sub-make; -k keeps going so one failure does not hide
# the others, and the exit status still fails on any failure.
INTEGRATION_JOBS ?= 4
CI_INTEGRATION_TARGETS := demo doctor mcp-control-smoke thread-smoke health-smoke notify-smoke store-smoke api-smoke live-api-smoke auth-smoke import-smoke bridge-smoke bridge-lint-smoke bridge-e2e-smoke bridge-dogfood-smoke self-dogfood-smoke readiness-smoke audit-smoke benchmark-smoke evidence-smoke release-candidate-smoke release-candidate-e2e-smoke package-smoke synthetic-restore-drill
ci-integration:
	@$(MAKE) -j$(INTEGRATION_JOBS) -k $(CI_INTEGRATION_TARGETS)

ci: dependency-audit release-scan ci-preflight test ci-integration npm-package-smoke scan release-boundary license-check
