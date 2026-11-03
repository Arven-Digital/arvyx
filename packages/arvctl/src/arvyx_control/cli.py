from __future__ import annotations

from .diagnostics import boundary, capture

import argparse
import dataclasses
import json
import os
from pathlib import Path
import re
import socket
import sys

from . import __version__
from .api import handle_api_request, serve_api
from .audit import run_audit
from .audit_log import append_audit, append_audit_once, verify_chain
from .auth import issue_token, list_tokens, renew_token, revoke_token
from .brokers import find_secret_refs, is_secret_ref, list_brokers, resolve_ref
from .benchmark import run_recall_benchmark
from .checkpoint_jobs import index_rebuild_status, rebuild_index_checkpointed
from .session import get_session, set_session
from .bridge import build_bridge_policy, write_bridge_policy
from .control import (
    THREAD_SEVERITIES,
    THREAD_TYPES,
    accept_handoff,
    acknowledge_thread,
    approve_request,
    complete_task,
    complete_handoff,
    complete_thread,
    consume_approval,
    create_handoff,
    create_task,
    list_approvals,
    list_bus_messages,
    list_handoffs,
    list_pending_threads,
    list_tasks,
    list_thread_inbox,
    post_bus_message,
    post_thread,
    post_thread_message,
    read_all_threads,
    read_thread,
    recover_torn_final_event,
    request_approval,
    review_handoff,
)
from .defaults import DEFAULT_BENCHMARK_CASES
from .defaults import DEFAULT_VAULT
from .defaults import ensure_repo_checkout
from .defaults import resolve_default_benchmark_cases
from .defaults import resolve_default_vault
from .digest import build_digest
from .agent_delivery import probe_route_endpoint
from .dispatcher import load_route_document, load_routes, seal_route_document, validate_routes
from .doctor import doctor
from .projection_cache import (
    build_projection_checkpoint,
    inspect_checkpoint,
    verify_projection_checkpoint,
)
from . import projection_cache
from .dogfood import dogfood_live_api, dogfood_self
from .evidence import export_evidence
from .execution import (
    DEFAULT_FIRST_HEARTBEAT_SECONDS, MAX_LEASE_SECONDS,
    claim_execution, close_execution, deliver_execution_attempt, heartbeat_execution,
    hold_execution,
    queue_health, record_execution_failure, replay_execution,
)
from .watchdog import run_watchdog
from .delivery_canary import run_canary_command
from .delivery_probe import run_probe_command
from .liveness import WORKER_COMPONENT, write_tick_record
from .health import report_failures_to_bus, run_health
from .health_ops import agent_matrix, daily_handoff
from .forget import REASON_CATEGORIES, restore_forgotten, soft_forget
from .notifiers import NOTIFIER_ADAPTERS, notify_and_deliver
from .operation_journal import (
    journal_path,
    operation_record,
    pending_operation_records,
    reject_unknown_dispatch,
    transition_operation_state,
)
from .outbox import reconcile_ambiguous_delivery
from .receipts import project_subject_receipt
from .importers import import_basic_memory, import_markdown, import_obsidian
from .replica import DEFAULT_MAX_STALENESS_SECONDS, auto_failover, promote_replica, replica_status, sync_replica
from .mcp import handle_json_line, tools_for_profile
from .attestation import (
    MODEL_REVIEW_CUSTODY,
    MODEL_REVIEW_POLICY,
    NS_RUN_PROVENANCE,
    AttestationError,
    git_tree_sha,
    model_review_attestation_path,
    model_review_entry,
    sign_payload,
    validate_model_review_receipt_path,
)
from .mcp_client_evidence import attest_evidence_file, generate_mcp_client_evidence, validate_mcp_client_evidence
from .readiness import readiness
from .recall import RETRIEVAL_MODES, context_pack, excerpt, recall
from .release_host import release_host_report
from .release_candidate import release_candidate_report
from .store import manifest_state, sync_sqlite
from .vault import init_vault, run_demo
from .writes import list_pending, list_refining, promote_memory, refine_memory, reject_memory, suggest_memory


@boundary("cli")
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arvyx")
    parser.add_argument("--version", action="version", version=f"arvyx {__version__}")
    parser.add_argument("--authority-vault", type=Path, help="Actual vault for state-only commands; no inferred default")
    subcommands = parser.add_subparsers(dest="command", required=True)
    alert_dismissal = subcommands.add_parser("operator-alert-dismissal", help="Abandon one obsolete watchdog notification only; default dry-run, OS operator boundary.")
    alert_dismissal.add_argument("record_id")
    alert_dismissal.add_argument("--state", type=Path, required=True)
    alert_dismissal.add_argument("--manifest", type=Path, required=True)
    alert_dismissal.add_argument("--dry-run", action="store_true")
    alert_dismissal.add_argument("--apply", action="store_true")
    alert_dismissal.add_argument("--json", action="store_true", dest="json_output")
    operator_archive = subcommands.add_parser("operator-archive", help="Exact current-operator non-success archival; one record, default dry-run.")
    operator_archive.add_argument("record_id")
    operator_archive.add_argument("--state", type=Path, required=True)
    operator_archive.add_argument("--manifest", type=Path, required=True)
    operator_archive.add_argument("--dry-run", action="store_true")
    operator_archive.add_argument("--apply", action="store_true")
    operator_archive.add_argument("--json", action="store_true", dest="json_output")

    recall_parser = subcommands.add_parser("recall", help="Recall a compact cited answer.")
    recall_parser.add_argument("question")
    recall_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    recall_parser.add_argument("--project")
    recall_parser.add_argument("--max-tokens", type=int, default=350)
    recall_parser.add_argument("--limit", type=int, default=4)
    recall_parser.add_argument("--retrieval-mode", choices=sorted(RETRIEVAL_MODES), default="lexical")
    recall_parser.add_argument("--recency-half-life-days", type=float, help="Temporal decay half-life; off if unset.")
    recall_parser.add_argument("--json", action="store_true", dest="json_output")

    excerpt_parser = subcommands.add_parser("excerpt", help="Read exact cited lines.")
    excerpt_parser.add_argument("source_path")
    excerpt_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    excerpt_parser.add_argument("--lines", required=True)
    excerpt_parser.add_argument("--max-tokens", type=int, default=220)
    excerpt_parser.add_argument("--json", action="store_true", dest="json_output")

    pack_parser = subcommands.add_parser("context-pack", help="Build a compact context pack.")
    pack_parser.add_argument("question")
    pack_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    pack_parser.add_argument("--project")
    pack_parser.add_argument("--max-tokens", type=int, default=700)
    pack_parser.add_argument("--limit", type=int, default=3)
    pack_parser.add_argument("--retrieval-mode", choices=sorted(RETRIEVAL_MODES), default="lexical")
    pack_parser.add_argument("--recency-half-life-days", type=float, help="Temporal decay half-life; off if unset.")
    pack_parser.add_argument("--json", action="store_true", dest="json_output")

    init_parser = subcommands.add_parser("init", help="Create a synthetic demo vault.")
    init_parser.add_argument("path", type=Path)
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--json", action="store_true", dest="json_output")

    demo_parser = subcommands.add_parser("demo", help="Run the synthetic memory demo checks.")
    demo_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    demo_parser.add_argument("--json", action="store_true", dest="json_output")

    doctor_parser = subcommands.add_parser("doctor", help="Check vault safety and structure.")
    doctor_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    doctor_parser.add_argument("--json", action="store_true", dest="json_output")

    index_parser = subcommands.add_parser("index", help="Run and inspect durable index jobs.")
    index_subcommands = index_parser.add_subparsers(dest="index_command", required=True)
    index_rebuild = index_subcommands.add_parser("rebuild", help="Run or resume a checkpointed index rebuild.")
    index_rebuild.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    index_rebuild.add_argument(
        "--owner", default=f"arvyx-index-worker@{socket.gethostname()}:{os.getpid()}"
    )
    index_rebuild.add_argument("--lease-seconds", type=int, default=60)
    index_rebuild.add_argument("--max-attempts", type=int, default=3)
    index_rebuild.add_argument("--json", action="store_true", dest="json_output")
    index_status = index_subcommands.add_parser("status", help="Show the checkpointed index job status.")
    index_status.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    index_status.add_argument("--json", action="store_true", dest="json_output")

    mcp_parser = subcommands.add_parser("mcp", help="Serve JSON-RPC MCP requests over stdio.")
    mcp_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    mcp_parser.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    mcp_parser.add_argument(
        "--audit-log",
        type=Path,
        default=Path("tmp/audit-log.jsonl"),
        help="Hash-chained audit log path for secret.resolve over stdio.",
    )
    mcp_parser.add_argument(
        "--profile",
        dest="mcp_profile",
        choices=["read-only", "agent", "operator"],
        default="read-only",
        help="MCP tool profile (default: read-only); operator trusts the client with mutation, approval, and secret tools.",
    )
    # Compatibility alias for existing automation. New commands and docs use
    # --profile so elevated operator access is conspicuous.
    mcp_parser.add_argument("--mcp-profile", dest="mcp_profile", choices=["read-only", "agent", "operator"], help=argparse.SUPPRESS)

    memory_parser = subcommands.add_parser("memory", help="Governed memory write lane.")
    memory_subcommands = memory_parser.add_subparsers(dest="memory_command", required=True)

    memory_suggest = memory_subcommands.add_parser("suggest", help="Suggest memory into the pending lane.")
    memory_suggest.add_argument("title")
    memory_suggest.add_argument("--content", help="Suggestion body text.")
    memory_suggest.add_argument("--file", type=Path, help="Read suggestion body from a file.")
    memory_suggest.add_argument("--author", required=True)
    memory_suggest.add_argument("--tag", action="append", dest="tags", default=[])
    memory_suggest.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_suggest.add_argument("--project", required=True)
    memory_suggest.add_argument("--json", action="store_true", dest="json_output")

    memory_pending = memory_subcommands.add_parser("pending", help="List pending memory suggestions.")
    memory_pending.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_pending.add_argument("--project", required=True)
    memory_pending.add_argument("--json", action="store_true", dest="json_output")

    memory_refine = memory_subcommands.add_parser(
        "refine", help="Claim a pending/imported suggestion into the refining lane."
    )
    memory_refine.add_argument("source_path")
    memory_refine.add_argument("--by", required=True, dest="refined_by")
    memory_refine.add_argument("--content", help="Refined body text (omit to move without rewriting).")
    memory_refine.add_argument("--file", type=Path, help="Read refined body from a file.")
    memory_refine.add_argument("--notes", default="")
    memory_refine.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_refine.add_argument("--project", required=True)
    memory_refine.add_argument("--json", action="store_true", dest="json_output")

    memory_refining = memory_subcommands.add_parser("refining", help="List the refining queue awaiting promotion.")
    memory_refining.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_refining.add_argument("--project", required=True)
    memory_refining.add_argument("--json", action="store_true", dest="json_output")

    memory_promote = memory_subcommands.add_parser("promote", help="Promote pending/imported/refined memory to curated notes.")
    memory_promote.add_argument("source_path")
    memory_promote.add_argument("--by", required=True, dest="promoted_by")
    memory_promote.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_promote.add_argument("--project", required=True)
    memory_promote.add_argument("--json", action="store_true", dest="json_output")

    memory_reject = memory_subcommands.add_parser("reject", help="Reject a pending suggestion into archive.")
    memory_reject.add_argument("source_path")
    memory_reject.add_argument("--by", required=True, dest="rejected_by")
    memory_reject.add_argument("--reason", default="")
    memory_reject.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_reject.add_argument("--project", required=True)
    memory_reject.add_argument("--json", action="store_true", dest="json_output")

    memory_forget = memory_subcommands.add_parser("forget", help="Soft-forget one exact curated source into the excluded archive.")
    memory_forget.add_argument("source_path")
    memory_forget.add_argument("--reason-category", required=True, choices=REASON_CATEGORIES)
    memory_forget.add_argument("--batch-id", required=True)
    memory_forget.add_argument("--by", required=True, dest="actor")
    memory_forget.add_argument("--idempotency-key", required=True)
    memory_forget.add_argument("--dry-run", action="store_true")
    memory_forget.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_forget.add_argument("--project", required=True)
    memory_forget.add_argument("--json", action="store_true", dest="json_output")

    memory_restore = memory_subcommands.add_parser("restore", help="Restore a soft-forgotten source without deleting its archive.")
    memory_restore.add_argument("tombstone_path")
    memory_restore.add_argument("--by", required=True, dest="actor")
    memory_restore.add_argument("--idempotency-key", required=True)
    memory_restore.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    memory_restore.add_argument("--json", action="store_true", dest="json_output")

    control_log_parser = subcommands.add_parser(
        "control-log", help="Operator-only append-log recovery commands."
    )
    control_log_subcommands = control_log_parser.add_subparsers(dest="control_log_command", required=True)
    recover_final = control_log_subcommands.add_parser(
        "recover-torn-final", help="Quarantine and remove only an invalid final partial event."
    )
    recover_final.add_argument("--state", type=Path, required=True)
    recover_final.add_argument("--json", action="store_true", dest="json_output")

    projection_build = control_log_subcommands.add_parser(
        "projection-checkpoint",
        help="Derive the read-path projection checkpoint from the whole log.",
    )
    projection_build.add_argument("--state", type=Path, required=True)
    projection_build.add_argument(
        "--min-tail-bytes",
        type=int,
        default=projection_cache.DEFAULT_MIN_TAIL_BYTES,
        help="Skip the write unless this many uncovered bytes have accumulated.",
    )
    projection_build.add_argument(
        "--force",
        action="store_true",
        help="Rebuild even when the uncovered tail is below the threshold.",
    )
    projection_build.add_argument(
        "--max-log-bytes",
        type=int,
        default=projection_cache.DEFAULT_MAX_LOG_BYTES,
        help="Refuse to build above this log size; 0 disables the ceiling.",
    )
    projection_build.add_argument("--json", action="store_true", dest="json_output")

    projection_status = control_log_subcommands.add_parser(
        "projection-status",
        help="Report whether the derived projection checkpoint is present and valid.",
    )
    projection_status.add_argument("--state", type=Path, required=True)
    projection_status.add_argument("--json", action="store_true", dest="json_output")

    projection_verify = control_log_subcommands.add_parser(
        "projection-verify",
        help="Re-derive every projection from the whole log and compare it with the checkpoint.",
    )
    projection_verify.add_argument("--state", type=Path, required=True)
    projection_verify.add_argument("--json", action="store_true", dest="json_output")

    task_parser = subcommands.add_parser("task", help="Manage local append-only demo tasks.")
    task_subcommands = task_parser.add_subparsers(dest="task_command", required=True)

    task_create = task_subcommands.add_parser("create", help="Create a task event.")
    task_create.add_argument("title")
    task_create.add_argument("--owner", default="")
    task_create.add_argument("--idempotency-key")
    task_create.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    task_create.add_argument("--json", action="store_true", dest="json_output")

    task_list = task_subcommands.add_parser("list", help="List projected task state.")
    task_list.add_argument("--status")
    task_list.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    task_list.add_argument("--json", action="store_true", dest="json_output")

    task_done = task_subcommands.add_parser("done", help="Complete a task.")
    task_done.add_argument("task_id")
    task_done.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    task_done.add_argument("--json", action="store_true", dest="json_output")

    approval_parser = subcommands.add_parser("approval", help="Manage command-hash approvals.")
    approval_subcommands = approval_parser.add_subparsers(dest="approval_command", required=True)

    approval_request = approval_subcommands.add_parser("request", help="Request approval for a command.")
    approval_request.add_argument("command_text")
    approval_request.add_argument("--requester", default="")
    approval_request.add_argument("--reason", default="")
    approval_request.add_argument("--ttl-seconds", type=int, default=3600)
    approval_request.add_argument("--idempotency-key")
    approval_request.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    approval_request.add_argument("--json", action="store_true", dest="json_output")

    approval_approve = approval_subcommands.add_parser("approve", help="Approve a command request.")
    approval_approve.add_argument("approval_id")
    approval_approve.add_argument("--approver", default="operator")
    approval_approve.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    approval_approve.add_argument("--json", action="store_true", dest="json_output")

    approval_consume = approval_subcommands.add_parser("consume", help="Consume an approved command.")
    approval_consume.add_argument("approval_id")
    approval_consume.add_argument("command_text")
    approval_consume.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    approval_consume.add_argument("--json", action="store_true", dest="json_output")

    approval_list = approval_subcommands.add_parser("list", help="List projected approval state.")
    approval_list.add_argument("--status")
    approval_list.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    approval_list.add_argument("--json", action="store_true", dest="json_output")

    handoff_parser = subcommands.add_parser("handoff", help="Manage append-only handoff events.")
    handoff_subcommands = handoff_parser.add_subparsers(dest="handoff_command", required=True)

    handoff_create = handoff_subcommands.add_parser("create", help="Create a handoff.")
    handoff_create.add_argument("title")
    handoff_create.add_argument("--from-agent", default="")
    handoff_create.add_argument("--to-agent", default="operator")
    handoff_create.add_argument("--summary", default="")
    handoff_create.add_argument("--idempotency-key")
    handoff_create.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    handoff_create.add_argument("--json", action="store_true", dest="json_output")

    handoff_list = handoff_subcommands.add_parser("list", help="List projected handoff state.")
    handoff_list.add_argument("--status")
    handoff_list.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    handoff_list.add_argument("--json", action="store_true", dest="json_output")

    handoff_accept = handoff_subcommands.add_parser("accept", help="Accept a handoff.")
    handoff_accept.add_argument("handoff_id")
    handoff_accept.add_argument("--actor", default="operator")
    handoff_accept.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    handoff_accept.add_argument("--json", action="store_true", dest="json_output")

    handoff_review = handoff_subcommands.add_parser("review", help="Review an accepted handoff.")
    handoff_review.add_argument("handoff_id")
    handoff_review.add_argument("--reviewer", default="operator")
    handoff_review.add_argument("--decision", choices=["approved", "changes_requested", "blocked"], default="approved")
    handoff_review.add_argument("--notes", default="")
    handoff_review.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    handoff_review.add_argument("--json", action="store_true", dest="json_output")

    handoff_complete = handoff_subcommands.add_parser("complete", help="Complete an accepted handoff.")
    handoff_complete.add_argument("handoff_id")
    handoff_complete.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    handoff_complete.add_argument("--json", action="store_true", dest="json_output")

    bus_parser = subcommands.add_parser("bus", help="Manage append-only bus messages.")
    bus_subcommands = bus_parser.add_subparsers(dest="bus_command", required=True)

    bus_post = bus_subcommands.add_parser("post", help="Post a bus message.")
    bus_post.add_argument("message")
    bus_post.add_argument("--channel", default="ops")
    bus_post.add_argument("--actor", default="")
    bus_post.add_argument("--severity", default="notice")
    bus_post.add_argument("--idempotency-key")
    bus_post.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    bus_post.add_argument("--json", action="store_true", dest="json_output")

    bus_list = bus_subcommands.add_parser("list", help="List bus messages.")
    bus_list.add_argument("--channel")
    bus_list.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    bus_list.add_argument("--json", action="store_true", dest="json_output")

    thread_parser = subcommands.add_parser("thread", help="War Room-style threaded inbox coordination.")
    thread_subcommands = thread_parser.add_subparsers(dest="thread_command", required=True)

    thread_post = thread_subcommands.add_parser("post", help="Post a new thread.")
    thread_post.add_argument("--title", required=True)
    thread_post.add_argument("--text", default="", help="Thread body text.")
    thread_post.add_argument("--type", choices=sorted(THREAD_TYPES), default="ask", dest="thread_type")
    thread_post.add_argument("--to", default="operator", dest="target")
    thread_post.add_argument("--actor", default="")
    thread_post.add_argument("--channel", default="ops")
    thread_post.add_argument("--severity", choices=sorted(THREAD_SEVERITIES), default="notice")
    thread_post.add_argument("--completion-artifact", default="")
    thread_post.add_argument("--completion-anchor", default="")
    thread_post.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_post.add_argument("--json", action="store_true", dest="json_output")

    thread_reply = thread_subcommands.add_parser("reply", help="Post a follow-up message to a thread.")
    thread_reply.add_argument("thread_id")
    thread_reply.add_argument("--text", required=True)
    thread_reply.add_argument("--actor", default="")
    thread_reply.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_reply.add_argument("--json", action="store_true", dest="json_output")

    thread_inbox = thread_subcommands.add_parser("inbox", help="List all threads targeting an agent.")
    thread_inbox.add_argument("target")
    thread_inbox.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_inbox.add_argument("--json", action="store_true", dest="json_output")

    thread_pending = thread_subcommands.add_parser("pending", help="List pending actionable threads for an agent.")
    thread_pending.add_argument("target")
    thread_pending.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_pending.add_argument("--json", action="store_true", dest="json_output")

    thread_ack = thread_subcommands.add_parser("ack", help="Acknowledge a thread (stays pending until done).")
    thread_ack.add_argument("thread_id")
    thread_ack.add_argument("--actor", default="operator")
    thread_ack.add_argument("--text", default="", help="Optional acknowledgement note.")
    thread_ack.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_ack.add_argument("--json", action="store_true", dest="json_output")

    thread_retire = thread_subcommands.add_parser("retire", help="Operator-only exact watchdog alert retirement, not completion.")
    thread_retire.add_argument("thread_id")
    thread_retire.add_argument("--state", type=Path, required=True)
    thread_retire.add_argument("--manifest", type=Path, required=True, help="One exact request JSON object, never a batch.")
    thread_retire.add_argument("--dry-run", action="store_true", help="Validate without appending (default).")
    thread_retire.add_argument("--apply", action="store_true", help="Append this exact locally authorized retirement.")
    thread_retire.add_argument("--json", action="store_true", dest="json_output")

    thread_done = thread_subcommands.add_parser("done", help="Complete a thread and clear it from pending.")
    thread_done.add_argument("thread_id")
    thread_done.add_argument("--actor", default="operator")
    thread_done.add_argument("--text", default="", help="Optional completion note.")
    thread_done.add_argument("--evidence-artifact", default="")
    thread_done.add_argument("--evidence-anchor", default="")
    thread_done.add_argument("--evidence-method", default="")
    thread_done.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_done.add_argument("--json", action="store_true", dest="json_output")

    thread_read = thread_subcommands.add_parser("read", help="Mark one thread as read.")
    thread_read.add_argument("thread_id")
    thread_read.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_read.add_argument("--json", action="store_true", dest="json_output")

    thread_read_all = thread_subcommands.add_parser("read-all", help="Mark an agent's non-pending threads as read.")
    thread_read_all.add_argument("target")
    thread_read_all.add_argument("--include-pending", action="store_true", dest="include_pending")
    thread_read_all.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    thread_read_all.add_argument("--json", action="store_true", dest="json_output")

    store_parser = subcommands.add_parser("store", help="Project append-only control events into stores.")
    store_subcommands = store_parser.add_subparsers(dest="store_command", required=True)

    store_sync = store_subcommands.add_parser("sync", help="Project JSONL control events into SQLite.")
    store_sync.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    store_sync.add_argument("--db", type=Path, default=Path("tmp/control.sqlite"))
    store_sync.add_argument("--retain-events", type=int)
    store_sync.add_argument("--json", action="store_true", dest="json_output")

    store_manifest = store_subcommands.add_parser("manifest", help="Summarize an append-only control log.")
    store_manifest.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    store_manifest.add_argument("--json", action="store_true", dest="json_output")

    auth_parser = subcommands.add_parser("auth", help="Issue and manage per-agent bearer tokens.")
    auth_subcommands = auth_parser.add_subparsers(dest="auth_command", required=True)

    auth_issue = auth_subcommands.add_parser("issue", help="Issue a token for a registry agent.")
    auth_issue.add_argument("agent_id")
    auth_issue.add_argument("--scope", action="append", dest="scopes")
    auth_issue.add_argument("--slot", help="Independent token slot; omitted keeps the legacy per-agent token path.")
    auth_ttl = auth_issue.add_mutually_exclusive_group()
    auth_ttl.add_argument("--ttl-days", type=int)
    auth_ttl.add_argument(
        "--ttl-seconds",
        type=int,
        help="Short-lived token TTL for bounded validation; defaults to 30 days when omitted.",
    )
    auth_issue.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    auth_issue.add_argument("--json", action="store_true", dest="json_output")

    auth_renew = auth_subcommands.add_parser(
        "renew",
        help="Re-issue an unrevoked token slot with its current scopes. stdout carries ONLY the token "
             "(pipe it straight to the agent host); metadata goes to stderr as JSON.",
    )
    auth_renew.add_argument("agent_id")
    auth_renew.add_argument("--slot", help="Token slot to renew; omitted renews the legacy default slot.")
    auth_renew.add_argument("--ttl-days", type=int, default=30)
    auth_renew.add_argument("--vault", type=Path, default=DEFAULT_VAULT)

    auth_revoke = auth_subcommands.add_parser("revoke", help="Revoke an agent token.")
    auth_revoke.add_argument("agent_id")
    auth_revoke.add_argument("--slot", help="Token slot to revoke; omitted revokes the legacy default slot.")
    auth_revoke.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    auth_revoke.add_argument("--json", action="store_true", dest="json_output")

    auth_list = auth_subcommands.add_parser("list", help="List issued agent tokens (hashes only).")
    auth_list.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    auth_list.add_argument("--json", action="store_true", dest="json_output")

    api_parser = subcommands.add_parser("api-call", help="Call the local Control Center API router.")
    api_parser.add_argument("method")
    api_parser.add_argument("path")
    api_parser.add_argument("--body", default="{}")
    api_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    api_parser.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    api_parser.add_argument("--idempotency-key")
    api_auth = api_parser.add_mutually_exclusive_group()
    api_auth.add_argument("--auth-env")
    api_auth.add_argument("--auth-file", type=Path)
    api_parser.add_argument("--allow-unauthenticated-demo", action="store_true")
    api_parser.add_argument("--mcp-profile", choices=["read-only", "agent", "operator"], default="read-only")

    operation_parser = subcommands.add_parser(
        "operation", help="Inspect and explicitly reconcile durable API operation records."
    )
    operation_subcommands = operation_parser.add_subparsers(dest="operation_command", required=True)
    operation_list = operation_subcommands.add_parser("list", help="List pending operations without key material.")
    operation_list.add_argument("--audit-log", type=Path, required=True)
    operation_list.add_argument("--state", type=Path, help="Exact original API/MCP state path; omit only for a vault-only journal")
    operation_list.add_argument("--limit", type=int, default=100)
    operation_list.add_argument("--json", action="store_true", dest="json_output")
    operation_reconcile = operation_subcommands.add_parser(
        "reconcile", help="Resolve an inspected ambiguous dispatch or finish a pending audit receipt."
    )
    operation_reconcile.add_argument("operation_id")
    operation_reconcile.add_argument("--audit-log", type=Path, required=True)
    operation_reconcile.add_argument("--state", type=Path, help="Exact original API/MCP state path; omit only for a vault-only journal")
    operation_reconcile.add_argument(
        "--resolution", choices=["reject-unknown", "complete-audit"], required=True
    )
    operation_reconcile.add_argument("--confirm-unknown-may-have-dispatched", action="store_true")
    operation_reconcile.add_argument("--json", action="store_true", dest="json_output")

    serve_parser = subcommands.add_parser("serve-api", help="Serve the local Control Center API.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    serve_parser.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    serve_auth = serve_parser.add_mutually_exclusive_group()
    serve_auth.add_argument("--auth-env")
    serve_auth.add_argument("--auth-file", type=Path)
    serve_parser.add_argument("--allow-unauthenticated-demo", action="store_true")
    serve_parser.add_argument("--audit-log", type=Path, help="Hash-chained audit log path (default: <state dir>/audit-log.jsonl)")
    serve_parser.add_argument("--delivery-routes", type=Path, required=True, help="Authoritative agent-delivery route configuration")
    serve_parser.add_argument("--mcp-profile", choices=["read-only", "agent", "operator"], default="read-only")

    session_parser = subcommands.add_parser("session", help="Read/write an agent's hot session state.")
    session_subcommands = session_parser.add_subparsers(dest="session_command", required=True)

    session_get = session_subcommands.add_parser("get", help="Read an agent's session state for a zero-ramp-up start.")
    session_get.add_argument("agent")
    session_get.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    session_get.add_argument("--json", action="store_true", dest="json_output")

    session_set = session_subcommands.add_parser("set", help="Replace an agent's session state (hot working memory).")
    session_set.add_argument("agent")
    session_set.add_argument("--content", help="Session state body text.")
    session_set.add_argument("--file", type=Path, help="Read session state body from a file.")
    session_set.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    session_set.add_argument("--json", action="store_true", dest="json_output")

    secret_parser = subcommands.add_parser("secret", help="Resolve sanctioned secret references via a broker.")
    secret_subcommands = secret_parser.add_subparsers(dest="secret_command", required=True)

    secret_resolve = secret_subcommands.add_parser("resolve", help="Resolve a secret://broker/path reference.")
    secret_resolve.add_argument("ref")
    secret_resolve.add_argument("--repo", type=Path, default=Path("."), help="Base dir for .arvyx/secret-brokers.json.")
    secret_resolve.add_argument(
        "--audit-log",
        type=Path,
        default=Path("tmp/audit-log.jsonl"),
        help="Hash-chained audit log path; secret resolution fails closed if it cannot be written.",
    )
    secret_resolve.add_argument("--json", action="store_true", dest="json_output")

    secret_brokers = secret_subcommands.add_parser("brokers", help="List configured brokers (no values).")
    secret_brokers.add_argument("--repo", type=Path, default=Path("."))
    secret_brokers.add_argument("--json", action="store_true", dest="json_output")

    secret_scan = secret_subcommands.add_parser("scan", help="Find secret references in a file.")
    secret_scan.add_argument("file", type=Path)
    secret_scan.add_argument("--json", action="store_true", dest="json_output")

    replica_parser = subcommands.add_parser("replica", help="Backup-host replication of a memory vault.")
    replica_subcommands = replica_parser.add_subparsers(dest="replica_command", required=True)

    replica_sync = replica_subcommands.add_parser("sync", help="Pull the primary vault into a replica.")
    replica_sync.add_argument("--from", required=True, dest="source_url", help="Primary API base URL.")
    replica_sync.add_argument("--vault", type=Path, required=True, help="Replica vault directory.")
    replica_sync.add_argument("--auth-env", help="Env var holding the replica.read bearer token.")
    replica_sync.add_argument("--state-dir", type=Path, help="Also pull control/audit state files here.")
    replica_sync.add_argument("--timeout", type=float, default=30.0)
    replica_sync.add_argument("--json", action="store_true", dest="json_output")

    replica_status_parser = replica_subcommands.add_parser("status", help="Show replica sync freshness.")
    replica_status_parser.add_argument("--vault", type=Path, required=True)
    replica_status_parser.add_argument("--json", action="store_true", dest="json_output")

    replica_failover = replica_subcommands.add_parser(
        "failover", help="Promote this replica to primary (quorum-gated with --auto)."
    )
    replica_failover.add_argument("--vault", type=Path, required=True, help="Replica vault to promote.")
    replica_failover.add_argument("--from", dest="source_url", help="Primary API base URL to probe for --auto.")
    replica_failover.add_argument(
        "--peer", action="append", default=[], dest="peers", help="Peer replica base URL for quorum (repeatable)."
    )
    replica_failover.add_argument("--auth-env", help="Env var holding a bearer token for health probes.")
    replica_failover.add_argument("--timeout", type=float, default=5.0)
    replica_failover.add_argument(
        "--max-staleness-minutes", type=int, default=DEFAULT_MAX_STALENESS_SECONDS // 60,
        help="Positive automatic-failover freshness limit in minutes (default: 60); unknown or incomplete sync always refuses unless forced."
    )
    replica_failover.add_argument(
        "--auto",
        action="store_true",
        help="Quorum-gated promotion: primary unreachable, replica fresh, and a majority of the set (self + --peer) reachable. Requires at least one --peer; single-replica standbys use manual failover instead.",
    )
    replica_failover.add_argument(
        "--force", action="store_true", help="Promote regardless of primary health or quorum."
    )
    replica_failover.add_argument("--reason", default="manual")
    replica_failover.add_argument("--json", action="store_true", dest="json_output")

    health_parser = subcommands.add_parser("health", help="Run host health checks (cron-friendly).")
    health_parser.add_argument("--url", help="API base URL to probe, e.g. http://127.0.0.1:8765")
    health_parser.add_argument("--auth-env", help="Env var holding a bearer token for authenticated checks.")
    health_parser.add_argument("--recall-question", default="what is the current truth")
    health_parser.add_argument("--recall-project")
    health_parser.add_argument("--audit-log", type=Path, help="Verify this hash-chained audit log locally.")
    health_parser.add_argument("--replica-vault", type=Path, help="Check replica sync freshness for this vault.")
    health_parser.add_argument("--max-replica-age-minutes", type=int, default=60)
    health_parser.add_argument("--report-state", type=Path, help="Post an alert bus message here on failure.")
    health_parser.add_argument("--host-label", default="memory-host")
    health_parser.add_argument("--timeout", type=float, default=10.0)
    health_parser.add_argument("--json", action="store_true", dest="json_output")

    # optional subcommands; a bare `arvyx health` still runs the host checks
    health_subcommands = health_parser.add_subparsers(dest="health_command", required=False)

    health_matrix = health_subcommands.add_parser(
        "agent-matrix", help="Probe configured agent endpoints into an OK/WARN/FAIL/SKIP readiness matrix."
    )
    health_matrix.add_argument("--config", type=Path, default=Path("examples/local-dev/agents.json"))
    # own dest: the parent health parser also defines --timeout (default 10.0)
    health_matrix.add_argument("--timeout", type=float, default=5.0, dest="matrix_timeout")
    health_matrix.add_argument("--json", action="store_true", dest="json_output")

    health_daily = health_subcommands.add_parser(
        "daily-handoff", help="Create the daily health handoff threads, once per date."
    )
    health_daily.add_argument("--date", help="ISO date (YYYY-MM-DD); defaults to today (UTC).")
    health_daily.add_argument("--actor", default="operator")
    health_daily.add_argument("--config", type=Path, help="Required explicit JSON roles config; no built-in roster.")
    health_daily.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    health_daily.add_argument("--json", action="store_true", dest="json_output")

    health_notify = health_subcommands.add_parser(
        "notify-check", help="Compute notification/escalation candidates and deliver them via one adapter."
    )
    health_notify.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    health_notify.add_argument("--dedupe-window-minutes", type=int, default=240)
    health_notify.add_argument("--escalate-after-minutes", type=int, default=60)
    health_notify.add_argument("--dry-run", action="store_true", dest="dry_run")
    health_notify.add_argument(
        "--dashboard-url", help="Include this link in notification text (validated; loopback links stay local-only)."
    )
    health_notify.add_argument(
        "--adapter", choices=NOTIFIER_ADAPTERS, default="stdout", help="Delivery adapter; stdout is the safe default."
    )
    health_notify.add_argument("--deliveries", type=Path, help="JSONL delivery log path (file adapter).")
    health_notify.add_argument(
        "--webhook-url-env", help="Env var holding the webhook POST target (webhook adapter)."
    )
    health_notify.add_argument(
        "--config", type=Path, help="Notifier config JSON (telegram/webhook adapters; see examples/notifiers/)."
    )
    # own dest: the parent health parser also defines --timeout (default 10.0)
    health_notify.add_argument("--timeout", type=float, default=10.0, dest="notify_timeout")
    health_notify.add_argument("--json", action="store_true", dest="json_output")

    audit_log_parser = subcommands.add_parser("audit-log", help="Inspect the hash-chained server audit log.")
    audit_log_subcommands = audit_log_parser.add_subparsers(dest="audit_log_command", required=True)

    audit_log_verify = audit_log_subcommands.add_parser("verify", help="Verify the audit log hash chain.")
    audit_log_verify.add_argument("--log", type=Path, default=Path("tmp/audit-log.jsonl"))
    audit_log_verify.add_argument("--json", action="store_true", dest="json_output")

    import_parser = subcommands.add_parser("import", help="Import external memory into governed lanes.")
    import_subcommands = import_parser.add_subparsers(dest="import_command", required=True)

    import_markdown_parser = import_subcommands.add_parser("markdown", help="Import markdown into a project lane.")
    import_markdown_parser.add_argument("source", type=Path)
    import_markdown_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    import_markdown_parser.add_argument("--project", required=True)
    import_markdown_parser.add_argument("--dry-run", action="store_true")
    import_markdown_parser.add_argument("--json", action="store_true", dest="json_output")

    import_obsidian_parser = import_subcommands.add_parser("obsidian", help="Import an Obsidian markdown vault.")
    import_obsidian_parser.add_argument("source", type=Path)
    import_obsidian_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    import_obsidian_parser.add_argument("--project", required=True)
    import_obsidian_parser.add_argument("--dry-run", action="store_true")
    import_obsidian_parser.add_argument("--json", action="store_true", dest="json_output")

    import_basic_memory_parser = import_subcommands.add_parser(
        "basic-memory",
        help="Import a Basic Memory markdown export.",
    )
    import_basic_memory_parser.add_argument("source", type=Path)
    import_basic_memory_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    import_basic_memory_parser.add_argument("--project", required=True)
    import_basic_memory_parser.add_argument("--dry-run", action="store_true")
    import_basic_memory_parser.add_argument("--json", action="store_true", dest="json_output")

    bridge_parser = subcommands.add_parser("bridge-policy", help="Generate safe-mcp-bridge policy JSON.")
    bridge_parser.add_argument("--profile", choices=["read-only", "agent", "operator"], default="read-only")
    bridge_parser.add_argument("--upstream", default="http://127.0.0.1:8765/mcp")
    bridge_parser.add_argument("--auth-env", default="ARVYX_MCP_TOKEN")
    bridge_parser.add_argument("--output", type=Path)
    bridge_parser.add_argument("--json", action="store_true", dest="json_output")

    digest_parser = subcommands.add_parser(
        "digest", help="Start-of-session / weekly brief from control state and session memory."
    )
    digest_parser.add_argument("--agent", help="Scope the brief to one agent (its session, tasks, handoffs).")
    digest_parser.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    digest_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    digest_parser.add_argument("--window-hours", type=int, default=24, help="24 for a daily brief, 168 for weekly.")
    digest_parser.add_argument("--json", action="store_true", dest="json_output")

    readiness_parser = subcommands.add_parser("readiness", help="Report product readiness against release fronts.")
    readiness_parser.add_argument("--repo", type=Path, default=Path("."))
    readiness_parser.add_argument("--json", action="store_true", dest="json_output")

    audit_parser = subcommands.add_parser("audit", help="Run internal release-audit evidence checks.")
    audit_parser.add_argument("--repo", type=Path, default=Path("."))
    audit_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    audit_parser.add_argument("--json", action="store_true", dest="json_output")

    benchmark_parser = subcommands.add_parser("benchmark", help="Run repeatable quality benchmarks.")
    benchmark_subcommands = benchmark_parser.add_subparsers(dest="benchmark_command", required=True)

    benchmark_recall = benchmark_subcommands.add_parser("recall", help="Run recall golden-set benchmark.")
    benchmark_recall.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    benchmark_recall.add_argument("--cases", type=Path, default=DEFAULT_BENCHMARK_CASES)
    benchmark_recall.add_argument("--max-tokens", type=int, default=160)
    benchmark_recall.add_argument("--retrieval-mode", choices=sorted(RETRIEVAL_MODES), default="lexical")
    benchmark_recall.add_argument("--json", action="store_true", dest="json_output")

    evidence_parser = subcommands.add_parser("evidence", help="Create review evidence bundles.")
    evidence_subcommands = evidence_parser.add_subparsers(dest="evidence_command", required=True)

    evidence_export = evidence_subcommands.add_parser("export", help="Export release-review evidence JSON.")
    evidence_export.add_argument("--repo", type=Path, default=Path("."))
    evidence_export.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    evidence_export.add_argument("--benchmark-cases", type=Path, default=DEFAULT_BENCHMARK_CASES)
    evidence_export.add_argument("--output", type=Path)
    evidence_export.add_argument("--run-docker", action="store_true")
    evidence_export.add_argument("--run-bridge", action="store_true")
    evidence_export.add_argument("--mcp-client-evidence", type=Path)
    evidence_export.add_argument("--json", action="store_true", dest="json_output")

    evidence_mcp_client = evidence_subcommands.add_parser(
        "mcp-client",
        help="Generate and validate real stdio MCP client evidence JSON.",
    )
    evidence_mcp_client.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    evidence_mcp_client.add_argument("--client", default="arvyx-cli")
    evidence_mcp_client.add_argument("--output", type=Path)
    evidence_mcp_client.add_argument("--json", action="store_true", dest="json_output")

    evidence_sign = evidence_subcommands.add_parser(
        "sign",
        help="Sign an MCP client evidence file with a configured SSH identity.",
    )
    evidence_sign.add_argument("--evidence", type=Path, required=True, help="Evidence JSON file to sign in place.")
    evidence_sign.add_argument("--key", type=Path, required=True, help="SSH private key path (readable only by the signing process).")
    evidence_sign.add_argument("--principal", required=True, help="Signer identity; must be pinned in docs/trusted-signers.allowed.")
    evidence_sign.add_argument("--json", action="store_true", dest="json_output")

    release_candidate_parser = subcommands.add_parser(
        "release-candidate",
        help="Run the private-preview release candidate report.",
    )
    release_candidate_parser.add_argument("--repo", type=Path, default=Path("."))
    release_candidate_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    release_candidate_parser.add_argument(
        "--benchmark-cases",
        type=Path,
        default=DEFAULT_BENCHMARK_CASES,
    )
    release_candidate_parser.add_argument("--run-docker", action="store_true")
    release_candidate_parser.add_argument("--run-bridge", action="store_true")
    release_candidate_parser.add_argument("--mcp-client-evidence", type=Path)
    release_candidate_parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="Require CI-signed run-provenance for docker/bridge instead of a local run.",
    )
    release_candidate_parser.add_argument("--provenance-dir", type=Path, help="Directory of *.provenance.json files.")
    release_candidate_parser.add_argument("--json", action="store_true", dest="json_output")

    release_host_parser = subcommands.add_parser(
        "release-host",
        help="Collect release-host-only evidence and blockers.",
    )
    release_host_parser.add_argument("--repo", type=Path, default=Path("."))
    release_host_parser.add_argument("--run-docker", action="store_true")
    release_host_parser.add_argument("--run-bridge", action="store_true")
    release_host_parser.add_argument("--mcp-client-evidence", type=Path)
    release_host_parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="Require CI-signed run-provenance for docker/bridge instead of a local run.",
    )
    release_host_parser.add_argument("--provenance-dir", type=Path, help="Directory of *.provenance.json files.")
    release_host_parser.add_argument("--json", action="store_true", dest="json_output")

    attest_parser = subcommands.add_parser("attest", help="Produce provenance and multi-model release-review receipts.")
    attest_sub = attest_parser.add_subparsers(dest="attest_command", required=True)

    attest_provenance = attest_sub.add_parser("provenance", help="Sign CI run-provenance for a release-host check.")
    attest_provenance.add_argument("--check", required=True, choices=["docker_runtime", "safe_mcp_bridge_e2e"])
    attest_provenance.add_argument("--result", default="pass", choices=["pass", "fail"])
    attest_provenance.add_argument("--repo", type=Path, default=Path("."))
    attest_provenance.add_argument("--key", type=Path, required=True, help="CI signer SSH private key.")
    attest_provenance.add_argument("--principal", required=True, help="Pinned CI signer identity.")
    attest_provenance.add_argument("--workflow", default="", help="CI workflow ref for the record.")
    attest_provenance.add_argument("--output", type=Path, required=True)
    attest_provenance.add_argument("--json", action="store_true", dest="json_output")

    attest_review = attest_sub.add_parser("model-review", help="Attach one model review report to a release subject.")
    attest_review.add_argument("--subject", required=True, choices=["security-audit", "release-gate"])
    attest_review.add_argument("--provider", required=True)
    attest_review.add_argument("--model", required=True)
    attest_review.add_argument("--verdict", required=True, choices=["approve", "approve-with-findings", "block"])
    attest_review.add_argument("--scope", action="append", required=True, help="Reviewed area; repeat for multiple areas.")
    attest_review.add_argument("--report", type=Path, required=True, help="Review report under .arvyx/model-reviews/.")
    attest_review.add_argument("--repo", type=Path, default=Path("."))
    attest_review.add_argument("--output", type=Path, help="Receipt file (default .arvyx/release-reviews/<subject>.attestation.json).")
    attest_review.add_argument("--json", action="store_true", dest="json_output")

    attest_synthesis = attest_sub.add_parser("model-synthesis", help="Record the decision from the collected model reviews.")
    attest_synthesis.add_argument("--subject", required=True, choices=["security-audit", "release-gate"])
    attest_synthesis.add_argument("--decision", required=True, choices=["approve", "block"])
    attest_synthesis.add_argument("--synthesizer", required=True, help="Model or orchestrator recording the final comparison.")
    attest_synthesis.add_argument("--agreement", action="append", default=[])
    attest_synthesis.add_argument("--disagreement", action="append", default=[])
    attest_synthesis.add_argument("--resolution", required=True)
    attest_synthesis.add_argument("--repo", type=Path, default=Path("."))
    attest_synthesis.add_argument("--output", type=Path, help="Receipt file (default .arvyx/release-reviews/<subject>.attestation.json).")
    attest_synthesis.add_argument("--json", action="store_true", dest="json_output")

    dogfood_parser = subcommands.add_parser("dogfood", help="Run product dogfood checks.")
    dogfood_subcommands = dogfood_parser.add_subparsers(dest="dogfood_command", required=True)

    dogfood_self_parser = dogfood_subcommands.add_parser("self", help="Dogfood the repo against its own docs.")
    dogfood_self_parser.add_argument("--repo", type=Path, default=Path("."))
    dogfood_self_parser.add_argument("--run-docker", action="store_true")
    dogfood_self_parser.add_argument("--run-bridge", action="store_true")
    dogfood_self_parser.add_argument("--mcp-client-evidence", type=Path)
    dogfood_self_parser.add_argument("--json", action="store_true", dest="json_output")

    dogfood_live_api_parser = dogfood_subcommands.add_parser("live-api", help="Dogfood the live HTTP API.")
    dogfood_live_api_parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    dogfood_live_api_parser.add_argument("--json", action="store_true", dest="json_output")

    execution_parser = subcommands.add_parser("execution", help="Run the durable inter-agent execution queue.")
    execution_subcommands = execution_parser.add_subparsers(dest="execution_command", required=True)
    execution_worker = execution_subcommands.add_parser(
        "worker", help="Claim one execution and wake its bound runtime."
    )
    execution_worker.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_worker.add_argument("--worker", required=True)
    execution_worker.add_argument("--execution-id", help="Claim only this fresh pending execution; never retry. Mutually exclusive with --subject-id.")
    execution_worker.add_argument("--subject-id", help="Materialize/claim only this exact fresh assignment. Mutually exclusive with --execution-id.")
    execution_worker.add_argument("--target", help="Required canonical target for exact selection; not a queue filter.")
    execution_worker.add_argument("--routes", type=Path, required=True)
    execution_worker.add_argument("--lease-seconds", type=int, default=60)
    execution_worker.add_argument(
        "--first-heartbeat-seconds", type=int, default=None,
        help=(
            "Window after an accepted wake for the target's first identity-bound heartbeat "
            f"(default {DEFAULT_FIRST_HEARTBEAT_SECONDS}, or --lease-seconds when larger); "
            "must be at least --lease-seconds. Later heartbeats renew by --lease-seconds."
        ),
    )
    execution_worker.add_argument("--max-attempts", type=int, default=3)
    execution_worker.add_argument("--now", help="RFC3339 test/operator clock; omit for current UTC.")
    execution_worker.add_argument("--json", action="store_true", dest="json_output")
    execution_health = execution_subcommands.add_parser("health", help="Report durable execution queue health.")
    execution_health.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_health.add_argument("--capable-target", action="append", required=True, dest="capable_targets")
    execution_health.add_argument("--heartbeat-stale-seconds", type=int, default=300)
    execution_health.add_argument("--json", action="store_true", dest="json_output")
    execution_replay = execution_subcommands.add_parser(
        "replay", help="Give a dead-lettered or held execution a fresh attempt budget."
    )
    execution_replay.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_replay.add_argument("--execution-id", required=True)
    execution_replay.add_argument("--routes", type=Path, required=True)
    execution_replay.add_argument("--replayed-by", default="operator")
    execution_replay.add_argument("--json", action="store_true", dest="json_output")
    execution_hold = execution_subcommands.add_parser(
        "hold", help="Move an execution into the operator-attention HOLD state."
    )
    execution_hold.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_hold.add_argument("--execution-id", required=True)
    execution_hold.add_argument("--reason", required=True)
    execution_hold.add_argument("--held-by", default="operator")
    execution_hold.add_argument("--json", action="store_true", dest="json_output")
    execution_close = execution_subcommands.add_parser(
        "close",
        help="Close a held or dead-lettered execution as terminally not-actionable.",
    )
    execution_close.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_close.add_argument("--execution-id", required=True)
    execution_close.add_argument(
        "--resolution-category", required=True,
        choices=["superseded", "obsolete", "terminal_elsewhere", "no_longer_actionable"],
    )
    execution_close.add_argument("--reason", required=True)
    execution_close.add_argument("--closed-by", default="operator")
    execution_close.add_argument("--json", action="store_true", dest="json_output")
    execution_reconcile = execution_subcommands.add_parser(
        "reconcile-delivery",
        help="Resolve one ambiguous external delivery from provider readback.",
    )
    execution_reconcile.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_reconcile.add_argument("--outbox-id", required=True)
    execution_reconcile.add_argument("--outcome", choices=["delivered", "not_delivered", "unverifiable"], required=True)
    execution_reconcile.add_argument("--provider-receipt", default="")
    execution_reconcile.add_argument("--detail", default="")
    execution_reconcile.add_argument("--resolved-by", default="operator")
    execution_reconcile.add_argument("--json", action="store_true", dest="json_output")
    execution_receipt = execution_subcommands.add_parser(
        "receipt", help="Project five-leg evidence for one exact subject."
    )
    execution_receipt.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_receipt.add_argument("--subject-id", required=True)
    execution_receipt.add_argument("--json", action="store_true", dest="json_output")
    execution_watchdog = execution_subcommands.add_parser(
        "watchdog", help="Detect lifecycle gaps and apply one bounded remediation per subject."
    )
    execution_watchdog.add_argument("--state", type=Path, default=Path("tmp/control-events.jsonl"))
    execution_watchdog.add_argument("--routes", type=Path, required=True)
    execution_watchdog.add_argument("--worker", default="arvyx-watchdog")
    execution_watchdog.add_argument("--probe", action="store_true")
    execution_watchdog.add_argument("--no-escalate", action="store_true")
    execution_watchdog.add_argument("--receipt-stale-seconds", type=int, default=900)
    execution_watchdog.add_argument("--heartbeat-stale-seconds", type=int, default=300)
    execution_watchdog.add_argument("--now", help="RFC3339 test/operator clock; omit for current UTC.")
    execution_watchdog.add_argument(
        "--vault", type=Path, default=os.environ.get("ARVYX_TOKEN_EXPIRY_VAULT") or None,
        help="Vault whose token registry is checked for expiry (env ARVYX_TOKEN_EXPIRY_VAULT); omit to skip.",
    )
    execution_watchdog.add_argument("--token-expiry-days", type=int, default=7)
    execution_watchdog.add_argument(
        "--token-expiry-target", default=os.environ.get("ARVYX_TOKEN_EXPIRY_NOTIFY") or "operator",
        help="Thread target for token-expiry warnings (env ARVYX_TOKEN_EXPIRY_NOTIFY). 'operator' has no "
             "delivery route; name an agent so the warning actually reaches someone.",
    )
    execution_watchdog.add_argument(
        "--escalation-target", default=os.environ.get("ARVYX_WATCHDOG_ESCALATION_TARGET") or "operator",
        help="Thread target for HOLD/BLOCKED escalations (env ARVYX_WATCHDOG_ESCALATION_TARGET). 'operator' has "
             "no delivery route; name an agent so a stuck job reaches someone. Escalations about the "
             "watchdog's own threads stay on 'operator' so they cannot loop.",
    )
    execution_watchdog.add_argument(
        "--stale-escalation-seconds", type=int, default=2 * 3600,
        help="Page the escalation target about any thread stuck this long without progress, and any "
             "ambiguous delivery, unresolved dead letter or 24h-old decision (nothing stays stale).",
    )
    execution_watchdog.add_argument("--json", action="store_true", dest="json_output")

    thread_abandon = subcommands.add_parser(
        "thread-abandon",
        help="Operator-only: retire an open/ACKed thread that will never be finished, without claiming DONE "
             "(dry run by default; refused while execution work is live).",
    )
    thread_abandon.add_argument("thread_id")
    thread_abandon.add_argument("--state", type=Path, required=True)
    thread_abandon.add_argument("--reason", required=True)
    thread_abandon.add_argument("--approval-reference", required=True)
    thread_abandon.add_argument("--apply", action="store_true")
    thread_abandon.add_argument("--json", action="store_true", dest="json_output")

    delivery_waive = subcommands.add_parser(
        "receipt-waiver",
        help="Operator-only: baseline historical deliveries that will never get their receipt (dry run by default).",
    )
    delivery_waive.add_argument("--state", type=Path, required=True)
    delivery_waive.add_argument("--before", required=True, help="RFC3339; only gaps delivered before this are listed.")
    delivery_waive.add_argument("--reason", default="", help="Required with --apply; recorded on the waiver event.")
    delivery_waive.add_argument("--apply", action="store_true", help="Append the waiver for exactly the listed ids.")
    delivery_waive.add_argument("--json", action="store_true", dest="json_output")

    delivery_parser = subcommands.add_parser(
        "delivery", help="Out-of-band agent-delivery liveness checks (probe, canary)."
    )
    delivery_subcommands = delivery_parser.add_subparsers(dest="delivery_command", required=True)
    delivery_retire = delivery_subcommands.add_parser("retire", help="Operator-only exact obsolete legacy delivery retirement.")
    delivery_retire.add_argument("outbox_id")
    delivery_retire.add_argument("--state", type=Path, required=True)
    delivery_retire.add_argument("--manifest", type=Path, required=True, help="One exact request JSON object, never a batch.")
    delivery_retire.add_argument("--dry-run", action="store_true", help="Validate without appending (default).")
    delivery_retire.add_argument("--apply", action="store_true", help="Append this exact locally authorized retirement.")
    delivery_retire.add_argument("--json", action="store_true", dest="json_output")
    delivery_probe = delivery_subcommands.add_parser(
        "probe", help="Read-only delivery liveness probe; never wakes an agent."
    )
    delivery_probe.add_argument("--state", type=Path, required=True)
    delivery_probe.add_argument("--routes", type=Path, required=True)
    delivery_probe.add_argument("--window-minutes", type=float, default=60.0)
    delivery_probe.add_argument("--dispatcher-interval-seconds", type=int, default=10)
    delivery_probe.add_argument("--worker-interval-seconds", type=int, default=5)
    delivery_probe.add_argument(
        "--stale-multiplier", type=float, default=3.0,
        help="A tick record older than this multiple of its expected interval is stale.",
    )
    delivery_probe.add_argument(
        "--tick-component", action="append", choices=["dispatcher", "execution-worker"],
        help="Tick record to require (repeatable); default: both.",
    )
    delivery_probe.add_argument("--max-dead-letter-ratio", type=float, default=0.2)
    delivery_probe.add_argument("--max-failure-ratio", type=float, default=0.5)
    delivery_probe.add_argument("--min-outcomes", type=int, default=4)
    delivery_probe.add_argument("--max-undelivered-age-minutes", type=float, default=30.0)
    delivery_probe.add_argument("--delivery-grace-seconds", type=int, default=300)
    delivery_probe.add_argument("--max-scan-mib", type=float, default=512.0)
    delivery_probe.add_argument("--no-transport", action="store_true", help="Skip the route TCP connect check.")
    delivery_probe.add_argument("--notify-config", type=Path, help="Out-of-band notifier config (adapter JSON).")
    delivery_probe.add_argument("--realert-hours", type=float, default=6.0)
    delivery_probe.add_argument("--deadman-url-env", help="Env var holding the dead-man (healthchecks-style) https URL.")
    delivery_probe.add_argument("--deadman-url-file", type=Path, help="File holding the dead-man https URL.")
    delivery_probe.add_argument("--deadman-timeout-seconds", type=float, default=10.0)
    delivery_probe.add_argument("--label", default="", help="Short instance label for alert text.")
    delivery_probe.add_argument("--now", help="RFC3339 test/operator clock; omit for current UTC.")
    delivery_probe.add_argument("--json", action="store_true", dest="json_output")
    delivery_canary = delivery_subcommands.add_parser(
        "canary", help="Identity-bound end-to-end canary: wakes one agent with a marked ask thread."
    )
    delivery_canary.add_argument("--api", required=True, help="Control API base URL.")
    delivery_canary.add_argument("--auth-env", help="Env var holding the canary agent's own token.")
    delivery_canary.add_argument("--auth-file", type=Path, help="File holding the canary agent's own token.")
    delivery_canary.add_argument("--target", required=True)
    delivery_canary.add_argument(
        "--state", type=Path, required=True,
        help="Control log, read-only, to observe the target-owned legs of the chain.",
    )
    delivery_canary.add_argument("--timeout-seconds", type=int, default=900)
    delivery_canary.add_argument("--poll-seconds", type=float, default=15.0)
    delivery_canary.add_argument("--http-timeout-seconds", type=float, default=10.0)
    delivery_canary.add_argument("--notify-config", type=Path, help="Out-of-band notifier config (adapter JSON).")
    delivery_canary.add_argument("--realert-hours", type=float, default=6.0)
    delivery_canary.add_argument("--deadman-url-env", help="Env var holding the dead-man (healthchecks-style) https URL.")
    delivery_canary.add_argument("--deadman-url-file", type=Path, help="File holding the dead-man https URL.")
    delivery_canary.add_argument("--deadman-timeout-seconds", type=float, default=10.0)
    delivery_canary.add_argument("--label", default="", help="Short instance label for alert text.")
    delivery_canary.add_argument("--json", action="store_true", dest="json_output")

    routes_parser = subcommands.add_parser("routes", help="Inspect the agent-delivery route document.")
    routes_subcommands = routes_parser.add_subparsers(dest="routes_command", required=True)
    routes_doctor = routes_subcommands.add_parser(
        "doctor", help="Validate the versioned route document without resolving secret values."
    )
    routes_doctor.add_argument("--routes", type=Path, required=True)
    routes_doctor.add_argument("--probe", action="store_true", help="Bounded TCP connect to each route's host:port.")
    routes_doctor.add_argument("--json", action="store_true", dest="json_output")
    routes_seal = routes_subcommands.add_parser(
        "seal",
        help="Write a versioned route document from an existing one, so dispatcher ticks can attest a revision.",
    )
    routes_seal.add_argument("--routes", type=Path, required=True)
    routes_seal.add_argument("--revision", required=True)
    routes_seal.add_argument("--owner", required=True)
    routes_seal.add_argument(
        "--approved-at", required=True, help="Timezone-aware RFC3339 approval timestamp."
    )
    routes_seal.add_argument("--out", type=Path, help="Write the sealed document here; omitted with --in-place.")
    routes_seal.add_argument(
        "--in-place", action="store_true", help="Replace the source document atomically, preserving its mode and ACLs."
    )
    routes_seal.add_argument(
        "--dry-run", action="store_true", help="Report the planned metadata and sha256 without writing."
    )
    routes_seal.add_argument("--json", action="store_true", dest="json_output")

    args = parser.parse_args(argv)
    tokens = list(sys.argv[1:] if argv is None else argv)
    if getattr(args, "state", None) is not None and not getattr(args, "authority_vault", None):
        if not any(token == "--vault" or token.startswith("--vault=") for token in tokens):
            parser.error("--state requires explicit --vault or global --authority-vault; no vault is inferred")
    if getattr(args, "authority_vault", None) is not None and hasattr(args, "vault"):
        if any(token == "--vault" or token.startswith("--vault=") for token in tokens) and args.vault.resolve() != args.authority_vault.resolve():
            parser.error("--vault and --authority-vault must identify the same vault")
        args.vault = args.authority_vault
    # Resolve packaged defaults before binding; dispatch must not change the
    # vault identity underneath nested bound entry points.
    try:
        _prepare_default_paths(args)
        if getattr(args, "authority_vault", None) is not None:
            args.authority_vault = getattr(args, "vault", None) or resolve_default_vault(args.authority_vault)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    from .replica_authority import authority_context
    with authority_context(getattr(args, "authority_vault", None) or getattr(args, "vault", None), getattr(args, "state", None)):
        return _authority_dispatch(args, parser)


def _authority_dispatch(args, parser):
    if args.command == "operator-alert-dismissal":
        from .auth import OPERATOR_IDENTITY
        from .operator_archive import _pairs
        from .operator_alert_dismissal import dismiss_alert
        try:
            if args.apply and args.dry_run:
                raise ValueError("--apply and --dry-run are mutually exclusive")
            request = json.loads(args.manifest.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
            result = dismiss_alert(args.state, record_id=args.record_id, request=request,
                                   identity=OPERATOR_IDENTITY, dry_run=not args.apply)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "operator-archive":
        from .auth import OPERATOR_IDENTITY
        from .operator_archive import archive_record, _pairs
        try:
            if args.apply and args.dry_run:
                raise ValueError("--apply and --dry-run are mutually exclusive")
            request = json.loads(args.manifest.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
            result = archive_record(args.state, record_id=args.record_id, request=request,
                                    identity=OPERATOR_IDENTITY, dry_run=not args.apply)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if ((args.command == "thread" and args.thread_command == "retire")
            or (args.command == "delivery" and args.delivery_command == "retire")):
        # Local state-file CLI has the existing operator/OS trust boundary;
        # no body actor, agent impersonation, remote client, or automatic batch.
        from .auth import OPERATOR_IDENTITY
        from .retirement import retire_thread, retire_pending_delivery
        try:
            if args.apply and args.dry_run:
                raise ValueError("--apply and --dry-run are mutually exclusive")
            request = json.loads(args.manifest.read_text(encoding="utf-8"))
            if args.command == "thread":
                result = retire_thread(args.state, thread_id=args.thread_id, request=request,
                                       identity=OPERATOR_IDENTITY, dry_run=not args.apply)
            else:
                result = retire_pending_delivery(args.state, outbox_id=args.outbox_id, request=request,
                                                 identity=OPERATOR_IDENTITY, dry_run=not args.apply)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "index":
        try:
            if args.index_command == "rebuild":
                result = rebuild_index_checkpointed(
                    args.vault,
                    owner=args.owner,
                    lease_seconds=args.lease_seconds,
                    max_attempts=args.max_attempts,
                )
            else:
                result = index_rebuild_status(args.vault)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        payload = dataclasses.asdict(result)
        print(json.dumps(payload, sort_keys=True) if args.json_output else payload)
        return 0
    if args.command == "execution":
        if args.execution_command == "receipt":
            result = project_subject_receipt(args.state, subject_id=args.subject_id).to_dict()
            print(json.dumps(result, sort_keys=True) if args.json_output else result)
            return 0
        if args.execution_command == "health":
            capable = set(args.capable_targets)
            result = queue_health(
                args.state, execution_capable_targets=capable,
                heartbeat_stale_seconds=args.heartbeat_stale_seconds,
            )
            print(json.dumps(result, sort_keys=True) if args.json_output else result)
            return 0
        if args.execution_command == "hold":
            try:
                held = hold_execution(
                    args.state, execution_id=args.execution_id,
                    reason=args.reason, held_by=args.held_by,
                )
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            result = held.to_dict()
            print(json.dumps(result, sort_keys=True) if args.json_output else result)
            return 0
        if args.execution_command == "close":
            try:
                closed = close_execution(
                    args.state, execution_id=args.execution_id,
                    resolution_category=args.resolution_category,
                    reason=args.reason, closed_by=args.closed_by,
                )
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            result = closed.to_dict()
            print(json.dumps(result, sort_keys=True) if args.json_output else result)
            return 0
        if args.execution_command == "reconcile-delivery":
            try:
                reconciled = reconcile_ambiguous_delivery(
                    args.state,
                    outbox_id=args.outbox_id,
                    resolved_by=args.resolved_by,
                    outcome=args.outcome,
                    provider_receipt=args.provider_receipt,
                    detail=args.detail,
                )
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            result = reconciled.to_dict()
            print(json.dumps(result, sort_keys=True) if args.json_output else result)
            return 0
        if args.execution_command == "replay":
            try:
                routes = load_routes(args.routes)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"error: invalid execution routes: {exc}", file=sys.stderr)
                return 2
            try:
                from .execution import project_executions as _project_executions
                execution = _project_executions(args.state).get(args.execution_id)
                if execution is None:
                    raise ValueError(f"unknown execution: {args.execution_id}")
                if execution.target not in set(routes):
                    raise ValueError(
                        f"execution target is not configured for replay: {args.execution_id}"
                    )
                replayed = replay_execution(
                    args.state, execution_id=args.execution_id, replayed_by=args.replayed_by,
                )
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            result = replayed.to_dict()
            print(json.dumps(result, sort_keys=True) if args.json_output else result)
            return 0
        if args.execution_command == "watchdog":
            try:
                routes = load_routes(args.routes)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"error: invalid watchdog routes: {exc}", file=sys.stderr)
                return 2
            route_errors = validate_routes(routes, environ=os.environ)
            if not routes or route_errors:
                detail = "; ".join(route_errors) if route_errors else "no watchdog routes configured"
                print(f"error: {detail}", file=sys.stderr)
                return 2
            from datetime import datetime as _datetime
            watchdog_now = (
                _datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else None
            )
            report = run_watchdog(
                args.state, routes=routes, worker=args.worker, now=watchdog_now,
                probe=args.probe, escalate=not args.no_escalate,
                receipt_stale_seconds=args.receipt_stale_seconds,
                heartbeat_stale_seconds=args.heartbeat_stale_seconds,
                vault=Path(args.vault) if args.vault else None,
                token_expiry_days=args.token_expiry_days,
                token_expiry_target=args.token_expiry_target,
                escalation_target=args.escalation_target,
                stale_escalation_seconds=args.stale_escalation_seconds,
            )
            print(json.dumps(report, sort_keys=True) if args.json_output else report)
            # Detection findings are the tick's normal output, not a unit
            # failure; nonzero is reserved for configuration/runtime errors.
            return 0
        return _run_execution_worker(args)
    if args.command == "thread-abandon":
        from .retirement import abandon_stale_thread

        try:
            report = abandon_stale_thread(
                args.state, thread_id=args.thread_id, reason=args.reason,
                approval_reference=args.approval_reference, dry_run=not args.apply,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(report, sort_keys=True) if args.json_output else report)
        return 0
    if args.command == "receipt-waiver":
        from datetime import datetime as _datetime

        from .watchdog import receipt_waiver_candidates, waive_receipts

        try:
            before = _datetime.fromisoformat(args.before.replace("Z", "+00:00"))
            if before.tzinfo is None:
                raise ValueError("--before must carry a timezone")
            candidates = receipt_waiver_candidates(args.state, before=before)
            if args.apply:
                if not candidates:
                    report: dict[str, object] = {"waived": 0, "outbox_ids": [], "applied": True}
                else:
                    report = waive_receipts(
                        args.state, outbox_ids=[row["outbox_id"] for row in candidates], reason=args.reason,
                    )
                    report["applied"] = True
            else:
                report = {"applied": False, "candidates": candidates, "count": len(candidates)}
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(report, sort_keys=True) if args.json_output else report)
        return 0
    if args.command == "routes":
        return _run_routes_command(args)
    if args.command == "delivery":
        if args.delivery_command == "canary":
            return run_canary_command(args)
        return run_probe_command(args)
    if args.command == "recall":
        try:
            result = recall(
                question=args.question,
                vault=args.vault,
                project=args.project,
                max_tokens=args.max_tokens,
                limit=args.limit,
                retrieval_mode=args.retrieval_mode,
                recency_half_life_days=args.recency_half_life_days,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            for item in result.answer:
                print(f"- {item}")
            if result.sources:
                print("Sources:")
                for source in result.sources:
                    print(f"- {source.path}:{source.lines} score={source.score:.2f}")
            print(f"Confidence: {result.confidence:.2f}")
        return 0

    if args.command == "excerpt":
        try:
            result = excerpt(
                vault=args.vault,
                source_path=args.source_path,
                lines=args.lines,
                max_tokens=args.max_tokens,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            print(f"{result.path}:{result.lines}")
            print(result.text)
        return 0

    if args.command == "context-pack":
        try:
            result = context_pack(
                question=args.question,
                vault=args.vault,
                project=args.project,
                max_tokens=args.max_tokens,
                limit=args.limit,
                retrieval_mode=args.retrieval_mode,
                recency_half_life_days=args.recency_half_life_days,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            print("Answer:")
            for item in result.answer:
                print(f"- {item}")
            print("Excerpts:")
            for item in result.excerpts:
                print(f"## {item.path}:{item.lines}")
                print(item.text)
            print(f"Confidence: {result.confidence:.2f}")
        return 0

    if args.command == "init":
        try:
            result = init_vault(path=args.path, force=args.force)
        except (FileExistsError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            print(f"Created synthetic vault: {result.path}")
            print(f"Files: {len(result.files_created)}")
        return 0

    if args.command == "demo":
        result = run_demo(vault=args.vault)
        if args.json_output:
            print(result.to_json())
        else:
            for check in result.checks:
                status = "PASS" if check["ok"] else "FAIL"
                print(f"{status} {check['name']}")
        return 0 if result.ok else 1

    if args.command == "doctor":
        result = doctor(vault=args.vault)
        if args.json_output:
            print(result.to_json())
        else:
            status = "OK" if result.ok else "FAIL"
            print(
                f"{status} checked_files={result.checked_files} "
                f"indexed_files={result.indexed_files} registry_files={result.registry_files}"
            )
            for finding in result.findings:
                path = f" {finding.path}" if finding.path else ""
                print(f"{finding.severity.upper()} {finding.code}{path}: {finding.message}")
        return 0 if result.ok else 1

    if args.command == "mcp":
        # Persistent stdio session: real MCP clients hold the process
        # open across initialize -> initialized -> tools/* and expect
        # one JSON response line per request. Exit on stdin EOF.
        if args.mcp_profile == "agent":
            print(
                "error: the agent profile requires authenticated HTTP MCP so identity and token scopes can be enforced",
                file=sys.stderr,
            )
            return 1
        allowed = set(tools_for_profile(args.mcp_profile))
        handled = 0
        from .stdio_bounds import bounded_lines
        for line in bounded_lines(sys.stdin):
            if line is None:
                handled += 1
                print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid or oversized UTF-8 request"}}), flush=True)
                continue
            line = line.strip()
            if not line:
                continue
            response = handle_json_line(
                line,
                vault=args.vault,
                state=args.state,
                allowed_tools=allowed,
                secret_audit_log=args.audit_log,
                require_secret_audit=True,
            )
            handled += 1
            if response is not None:
                print(response, flush=True)
        if handled == 0:
            print("error: expected JSON-RPC requests on stdin", file=sys.stderr)
            return 1
        return 0

    if args.command == "auth":
        try:
            if args.auth_command == "issue":
                result = issue_token(
                    vault=args.vault,
                    agent_id=args.agent_id,
                    scopes=args.scopes,
                    ttl_days=args.ttl_days,
                    ttl_seconds=args.ttl_seconds,
                    slot=args.slot,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"token: {result.token}")
                    print("store it now; only its hash is kept on disk")
                    print(f"scopes: {', '.join(result.scopes)}")
                return 0
            if args.auth_command == "renew":
                result = renew_token(
                    vault=args.vault, agent_id=args.agent_id, slot=args.slot, ttl_days=args.ttl_days,
                )
                # The token is the only thing on stdout, so `renew ... | ssh host 'cat > file'`
                # moves it without it ever being printed or logged.
                sys.stdout.write(result.token)
                sys.stdout.flush()
                renewed = next(
                    record for record in list_tokens(vault=args.vault).tokens
                    if record.agent_id == result.agent_id and record.slot == result.slot
                )
                print(json.dumps({"renewed": f"{result.agent_id}/{result.slot}", "scopes": result.scopes,
                                  "expires_at": renewed.expires_at}, sort_keys=True), file=sys.stderr)
                return 0
            if args.auth_command == "revoke":
                record = revoke_token(vault=args.vault, agent_id=args.agent_id, slot=args.slot)
                if args.json_output:
                    print(json.dumps(record.to_dict(), sort_keys=True))
                else:
                    print(f"revoked {record.agent_id} slot={record.slot}")
                return 0
            if args.auth_command == "list":
                result = list_tokens(vault=args.vault)
                if args.json_output:
                    print(result.to_json())
                else:
                    for record in result.tokens:
                        status = "revoked" if record.revoked else "active"
                        print(f"{record.agent_id} {status} {record.issued_at} {','.join(record.scopes)} slot={record.slot}")
                return 0
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "memory":
        try:
            if args.memory_command == "suggest":
                if args.file is not None and args.content is not None:
                    print("error: pass either --content or --file, not both", file=sys.stderr)
                    return 1
                if args.file is not None:
                    content = args.file.read_text(encoding="utf-8")
                elif args.content is not None:
                    content = args.content
                else:
                    print("error: --content or --file is required", file=sys.stderr)
                    return 1
                result = suggest_memory(
                    vault=args.vault,
                    project=args.project,
                    title=args.title,
                    content=content,
                    author=args.author,
                    tags=args.tags or None,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"suggested {result.path}")
                return 0
            if args.memory_command == "pending":
                result = list_pending(vault=args.vault, project=args.project)
                if args.json_output:
                    print(result.to_json())
                else:
                    for entry in result.pending:
                        print(f"{entry.path} {entry.author} {entry.created_at} {entry.title}")
                return 0
            if args.memory_command == "refine":
                if args.file is not None and args.content is not None:
                    print("error: pass either --content or --file, not both", file=sys.stderr)
                    return 1
                if args.file is not None:
                    refined_content = args.file.read_text(encoding="utf-8")
                elif args.content is not None:
                    refined_content = args.content
                else:
                    refined_content = None
                result = refine_memory(
                    vault=args.vault,
                    project=args.project,
                    source_path=args.source_path,
                    refined_by=args.refined_by,
                    content=refined_content,
                    notes=args.notes,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"refining {result.source} -> {result.target}")
                return 0
            if args.memory_command == "refining":
                result = list_refining(vault=args.vault, project=args.project)
                if args.json_output:
                    print(result.to_json())
                else:
                    for entry in result.refining:
                        print(f"{entry.path} {entry.author} {entry.created_at} {entry.title}")
                return 0
            if args.memory_command == "promote":
                result = promote_memory(
                    vault=args.vault,
                    project=args.project,
                    source_path=args.source_path,
                    promoted_by=args.promoted_by,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"promoted {result.source} -> {result.target}")
                return 0
            if args.memory_command == "reject":
                result = reject_memory(
                    vault=args.vault,
                    project=args.project,
                    source_path=args.source_path,
                    rejected_by=args.rejected_by,
                    reason=args.reason,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"rejected {result.source} -> {result.target}")
                return 0
            if args.memory_command == "forget":
                result = soft_forget(
                    vault=args.vault, project=args.project, source_path=args.source_path,
                    reason_category=args.reason_category, batch_id=args.batch_id, actor=args.actor,
                    idempotency_key=args.idempotency_key, dry_run=args.dry_run,
                )
                print(result.to_json() if args.json_output else f"{result.status} {result.source_path} -> {result.archive_path}")
                return 0
            if args.memory_command == "restore":
                result = restore_forgotten(args.vault, args.tombstone_path, args.actor, args.idempotency_key)
                print(result.to_json() if args.json_output else f"restored {result.source_path}")
                return 0
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "control-log":
        try:
            if args.control_log_command == "recover-torn-final":
                receipt = recover_torn_final_event(args.state)
                if args.json_output:
                    print(json.dumps(receipt, sort_keys=True))
                else:
                    print(
                        f"Recovered {receipt['removed_bytes']} torn bytes to "
                        f"{receipt['quarantine_path']}"
                    )
                return 0
            if args.control_log_command == "projection-checkpoint":
                report = build_projection_checkpoint(
                    args.state,
                    force=args.force,
                    min_tail_bytes=args.min_tail_bytes,
                    max_log_bytes=args.max_log_bytes,
                )
                if args.json_output:
                    print(json.dumps(report, sort_keys=True))
                else:
                    print(
                        f"built={report['built']} reason={report['reason']} "
                        f"offset={report['log_offset']} tail={report['tail_bytes']}"
                    )
                # Healthy outcomes, including a bounded no-op, must not alarm a
                # wrapper: only a genuine failure exits non-zero.
                healthy = {
                    "built",
                    "bootstrap",
                    "nothing_new",
                    "tail_below_threshold",
                    "empty_log",
                    "no_log",
                }
                return 0 if report["reason"] in healthy else 1
            if args.control_log_command == "projection-status":
                status = inspect_checkpoint(args.state)
                if args.json_output:
                    print(json.dumps(status, sort_keys=True))
                else:
                    print(
                        f"present={status['present']} valid={status['valid']} "
                        f"reason={status['reason']} tail={status['tail_bytes']}"
                    )
                return 0
            if args.control_log_command == "projection-verify":
                verification = verify_projection_checkpoint(args.state)
                if args.json_output:
                    print(json.dumps(verification, sort_keys=True))
                else:
                    print(
                        f"ok={verification['ok']} reason={verification['reason']} "
                        f"disagrees_with_log={verification['disagrees_with_log']} "
                        f"mismatched={','.join(verification['mismatched'])}"
                    )
                # An invalid checkpoint is auto-rejected on the read path; only a
                # checkpoint that disagrees with the log is an incident.
                return 1 if verification["disagrees_with_log"] else 0
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print("error: unknown control-log command", file=sys.stderr)
        return 2

    if args.command == "task":
        try:
            if args.task_command == "create":
                result = create_task(state=args.state, title=args.title, owner=args.owner, idempotency_key=args.idempotency_key)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"created {result.task.id} {result.task.title}")
                return 0
            if args.task_command == "list":
                result = list_tasks(state=args.state, status=args.status)
                if args.json_output:
                    print(result.to_json())
                else:
                    for task in result.tasks:
                        print(f"{task.id} {task.status} {task.owner} {task.title}")
                return 0
            if args.task_command == "done":
                result = complete_task(state=args.state, task_id=args.task_id)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"done {result.task.id} {result.task.title}")
                return 0
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "approval":
        try:
            if args.approval_command == "request":
                result = request_approval(
                    state=args.state,
                    command=args.command_text,
                    requester=args.requester,
                    reason=args.reason,
                    ttl_seconds=args.ttl_seconds,
                    idempotency_key=args.idempotency_key,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"requested {result.approval.id} {result.approval.command_hash}")
                return 0
            if args.approval_command == "approve":
                result = approve_request(state=args.state, approval_id=args.approval_id, approver=args.approver)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"approved {result.approval.id}")
                return 0
            if args.approval_command == "consume":
                result = consume_approval(state=args.state, approval_id=args.approval_id, command=args.command_text)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"consumed {result.approval.id}")
                return 0
            if args.approval_command == "list":
                result = list_approvals(state=args.state, status=args.status)
                if args.json_output:
                    print(result.to_json())
                else:
                    for approval in result.approvals:
                        print(f"{approval.id} {approval.status} {approval.requester} {approval.command_hash}")
                return 0
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "handoff":
        try:
            if args.handoff_command == "create":
                result = create_handoff(
                    state=args.state,
                    title=args.title,
                    from_agent=args.from_agent,
                    to_agent=args.to_agent,
                    summary=args.summary,
                    idempotency_key=args.idempotency_key,
                    actor_identity_bound=False,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"created {result.handoff.id} {result.handoff.title}")
                return 0
            if args.handoff_command == "list":
                result = list_handoffs(state=args.state, status=args.status)
                if args.json_output:
                    print(result.to_json())
                else:
                    for handoff in result.handoffs:
                        print(
                            f"{handoff.id} {handoff.status} "
                            f"{handoff.from_agent}->{handoff.to_agent} {handoff.title}"
                        )
                return 0
            if args.handoff_command == "accept":
                result = accept_handoff(state=args.state, handoff_id=args.handoff_id, actor=args.actor)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"accepted {result.handoff.id} {result.handoff.title}")
                return 0
            if args.handoff_command == "review":
                result = review_handoff(
                    state=args.state,
                    handoff_id=args.handoff_id,
                    reviewer=args.reviewer,
                    decision=args.decision,
                    notes=args.notes,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"reviewed {result.handoff.id} {result.handoff.review_decision}")
                return 0
            if args.handoff_command == "complete":
                result = complete_handoff(state=args.state, handoff_id=args.handoff_id)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"completed {result.handoff.id} {result.handoff.title}")
                return 0
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "bus":
        if args.bus_command == "post":
            result = post_bus_message(
                state=args.state,
                message=args.message,
                channel=args.channel,
                actor=args.actor,
                severity=args.severity,
                idempotency_key=args.idempotency_key,
            )
            if args.json_output:
                print(result.to_json())
            else:
                print(f"posted {result.message.id} {result.message.channel}")
            return 0
        if args.bus_command == "list":
            result = list_bus_messages(state=args.state, channel=args.channel)
            if args.json_output:
                print(result.to_json())
            else:
                for message in result.messages:
                    print(f"{message.id} {message.channel} {message.severity} {message.actor}: {message.message}")
            return 0

    if args.command == "thread":
        try:
            if args.thread_command == "post":
                result = post_thread(
                    state=args.state,
                    title=args.title,
                    body=args.text,
                    thread_type=args.thread_type,
                    actor=args.actor,
                    target=args.target,
                    channel=args.channel,
                    severity=args.severity,
                    completion_artifact=args.completion_artifact,
                    completion_anchor=args.completion_anchor,
                    actor_identity_bound=False,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"created {result.thread.id} {result.thread.type} -> {result.thread.target} {result.thread.title}")
                return 0
            if args.thread_command == "reply":
                result = post_thread_message(
                    state=args.state,
                    thread_id=args.thread_id,
                    text=args.text,
                    actor=args.actor,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"replied {result.thread.id} {result.thread.title}")
                return 0
            if args.thread_command == "inbox":
                result = list_thread_inbox(state=args.state, target=args.target)
                if args.json_output:
                    print(result.to_json())
                else:
                    for thread in result.threads:
                        print(
                            f"{thread.id} {thread.status} {thread.type} {thread.severity} "
                            f"{thread.actor}->{thread.target} {thread.title}"
                        )
                return 0
            if args.thread_command == "pending":
                result = list_pending_threads(state=args.state, target=args.target)
                if args.json_output:
                    print(result.to_json())
                else:
                    for thread in result.threads:
                        print(
                            f"{thread.id} {thread.status} {thread.type} {thread.severity} "
                            f"{thread.actor}->{thread.target} {thread.title}"
                        )
                return 0
            if args.thread_command == "ack":
                result = acknowledge_thread(
                    state=args.state, thread_id=args.thread_id, actor=args.actor, text=args.text
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"acked {result.thread.id} {result.thread.title}")
                return 0
            if args.thread_command == "done":
                result = complete_thread(
                    state=args.state,
                    thread_id=args.thread_id,
                    actor=args.actor,
                    text=args.text,
                    evidence_artifact=args.evidence_artifact,
                    evidence_anchor=args.evidence_anchor,
                    evidence_method=args.evidence_method,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"done {result.thread.id} {result.thread.title}")
                return 0
            if args.thread_command == "read":
                result = read_thread(state=args.state, thread_id=args.thread_id)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"read {result.thread.id} {result.thread.title}")
                return 0
            if args.thread_command == "read-all":
                result = read_all_threads(
                    state=args.state, target=args.target, include_pending=args.include_pending
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"read {len(result.threads)} threads for {args.target}")
                return 0
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "store":
        if args.store_command == "sync":
            try:
                result = sync_sqlite(state=args.state, db=args.db, retain_events=args.retain_events)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if args.json_output:
                print(result.to_json())
            else:
                print(
                    f"synced events={result.events} tasks={result.tasks} "
                    f"approvals={result.approvals} retention={result.retention} db={result.db}"
                )
            return 0
        if args.store_command == "manifest":
            try:
                result = manifest_state(state=args.state)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if args.json_output:
                print(result.to_json())
            else:
                print(f"events={result.events} sha256={result.sha256}")
                print(f"first={result.first_timestamp or ''} last={result.last_timestamp or ''}")
                for event_type, count in result.event_types.items():
                    print(f"{event_type}={count}")
            return 0

    if args.command == "api-call":
        try:
            body = json.loads(args.body)
        except json.JSONDecodeError as exc:
            print(f"error: invalid JSON body: {exc.msg}", file=sys.stderr)
            return 1
        if not isinstance(body, dict):
            print("error: body must be a JSON object", file=sys.stderr)
            return 1
        try:
            credential = _credential_value(auth_env=args.auth_env, auth_file=args.auth_file)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        result = handle_api_request(
            method=args.method,
            path=args.path,
            body=body,
            vault=args.vault,
            state=args.state,
            bearer_secret=credential,
            authorization=f"Bearer {credential}" if credential else None,
            mcp_profile=args.mcp_profile,
            allow_unauthenticated_demo=args.allow_unauthenticated_demo,
            idempotency_key=args.idempotency_key,
        )
        print(result.to_json())
        return 0 if result.status < 400 else 1

    if args.command == "operation":
        store = journal_path(args.audit_log)
        try:
            if args.operation_command == "list":
                records = pending_operation_records(store, limit=args.limit)
                payload = {
                    "ok": True,
                    "operations": [
                        {
                            "operation_id": record.operation_id,
                            "principal_scope": record.principal_scope,
                            "action": record.action,
                            "state": record.state,
                            "http_status": record.http_status,
                            "created_at": record.created_at,
                            "updated_at": record.updated_at,
                        }
                        for record in records
                    ],
                }
                if args.json_output:
                    print(json.dumps(payload, sort_keys=True))
                else:
                    for record in payload["operations"]:
                        print(
                            f"{record['operation_id']} state={record['state']} "
                            f"action={record['action']} updated_at={record['updated_at']}"
                        )
                return 0

            record = operation_record(store, args.operation_id)
            if record is None:
                raise ValueError("operation does not exist")
            if args.resolution == "complete-audit":
                if record.state != "outcome_pending" or record.safe_outcome is None:
                    raise ValueError("complete-audit requires an outcome_pending operation with a safe outcome")
                append_audit_once(args.audit_log, record.safe_outcome)
                if not transition_operation_state(
                    store,
                    record.operation_id,
                    expected_state="outcome_pending",
                    new_state="completed",
                ):
                    raise RuntimeError("operation state changed during audit reconciliation")
                state = "completed"
            else:
                if not args.confirm_unknown_may_have_dispatched:
                    raise ValueError("reject-unknown requires --confirm-unknown-may-have-dispatched")
                if record.state != "dispatching":
                    raise ValueError("reject-unknown requires a dispatching operation")
                append_audit_once(
                    args.audit_log,
                    {
                        "event_id": f"{record.operation_id}:reconciliation",
                        "operation_id": record.operation_id,
                        "phase": "reconciliation",
                        "surface": "operator-cli",
                        "action": record.action,
                        "decision": "rejected-unknown",
                    },
                )
                if not reject_unknown_dispatch(store, record.operation_id):
                    raise RuntimeError("operation state changed during dispatch reconciliation")
                state = "rejected"
            payload = {
                "ok": True,
                "operation_id": record.operation_id,
                "state": state,
                "redispatched": False,
            }
            print(json.dumps(payload, sort_keys=True) if args.json_output else f"operation={record.operation_id} state={state} redispatched=false")
            return 0
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "serve-api":
        try:
            serve_api(
                host=args.host,
                port=args.port,
                vault=args.vault,
                state=args.state,
                bearer_secret=_credential_value(auth_env=args.auth_env, auth_file=args.auth_file),
                mcp_profile=args.mcp_profile,
                allow_unauthenticated_demo=args.allow_unauthenticated_demo,
                audit_log=args.audit_log,
                delivery_routes=args.delivery_routes,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.command == "session":
        try:
            if args.session_command == "get":
                result = get_session(vault=args.vault, agent=args.agent)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"# {result.agent} session (updated {result.updated_at})")
                    print(result.content)
                return 0
            if args.session_command == "set":
                if args.file is not None and args.content is not None:
                    print("error: pass either --content or --file, not both", file=sys.stderr)
                    return 1
                if args.file is not None:
                    content = args.file.read_text(encoding="utf-8")
                elif args.content is not None:
                    content = args.content
                else:
                    print("error: --content or --file is required", file=sys.stderr)
                    return 1
                result = set_session(vault=args.vault, agent=args.agent, content=content)
                if args.json_output:
                    print(result.to_json())
                else:
                    print(f"session updated: {result.path}")
                return 0
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "secret":
        try:
            if args.secret_command == "resolve":
                safe_ref = args.ref if is_secret_ref(args.ref) else "invalid-secret-ref"
                try:
                    append_audit(
                        args.audit_log,
                        {
                            "surface": "cli",
                            "command": "secret.resolve",
                            "secret_ref": safe_ref,
                            "identity": "operator",
                            "decision": "pending",
                        },
                    )
                except OSError:
                    print("error: audit log write failed; refusing to resolve secret", file=sys.stderr)
                    return 1
                try:
                    resolved = resolve_ref(args.ref, repo=args.repo)
                except (FileNotFoundError, ValueError):
                    try:
                        append_audit(
                            args.audit_log,
                            {
                                "surface": "cli",
                                "command": "secret.resolve",
                                "secret_ref": safe_ref,
                                "identity": "operator",
                                "decision": "denied",
                            },
                        )
                    except OSError:
                        pass
                    print("error: secret resolution failed", file=sys.stderr)
                    return 1
                try:
                    append_audit(
                        args.audit_log,
                        {
                            "surface": "cli",
                            "command": "secret.resolve",
                            "secret_ref": safe_ref,
                            "identity": "operator",
                            "decision": "allowed",
                        },
                    )
                except OSError:
                    print("error: audit completion write failed; refusing to print secret", file=sys.stderr)
                    return 1
                if args.json_output:
                    print(json.dumps(resolved.to_dict(include_value=True), sort_keys=True))
                else:
                    # value to stdout only, nothing else, so it pipes cleanly
                    print(resolved.value)
                return 0
            if args.secret_command == "brokers":
                brokers = list_brokers(repo=args.repo)
                if args.json_output:
                    print(json.dumps({"brokers": brokers}, sort_keys=True))
                else:
                    for broker in brokers:
                        print(f"{broker['name']}\t{broker['provider']}")
                return 0
            if args.secret_command == "scan":
                text = args.file.read_text(encoding="utf-8")
                refs = [ref.uri for ref in find_secret_refs(text)]
                if args.json_output:
                    print(json.dumps({"refs": refs}, sort_keys=True))
                else:
                    for ref in refs:
                        print(ref)
                return 0
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "replica":
        try:
            if args.replica_command == "sync":
                result = sync_replica(
                    source_url=args.source_url,
                    vault=args.vault,
                    token=_env_value(args.auth_env),
                    state_dir=args.state_dir,
                    timeout=args.timeout,
                )
                if args.json_output:
                    print(result.to_json())
                else:
                    print(
                        f"synced from {result.source}: fetched={len(result.fetched)} "
                        f"unchanged={result.unchanged} deleted={len(result.deleted)} "
                        f"state={','.join(result.state_fetched) or 'none'}"
                    )
                return 0
            if args.replica_command == "status":
                result = replica_status(vault=args.vault)
                if args.json_output:
                    print(result.to_json())
                else:
                    if not result.is_replica:
                        print("not a replica vault")
                    else:
                        print(
                            f"replica of {result.source or 'unknown'} "
                            f"last_synced={result.last_synced_at or 'never'} "
                            f"age_seconds={result.age_seconds if result.age_seconds is not None else 'unknown'}"
                        )
                return 0 if result.is_replica else 1
            if args.replica_command == "failover":
                if args.auto:
                    if not args.source_url:
                        raise ValueError("--from primary URL is required for --auto failover")
                    result = auto_failover(
                        vault=args.vault,
                        source_url=args.source_url,
                        peers=tuple(args.peers),
                        timeout=args.timeout,
                        token=_env_value(args.auth_env),
                        max_staleness_seconds=(
                            args.max_staleness_minutes * 60 if args.max_staleness_minutes is not None else None
                        ),
                        force=args.force,
                    )
                else:
                    result = promote_replica(vault=args.vault, reason=args.reason)
                if args.json_output:
                    print(result.to_json())
                elif result.promoted:
                    print(
                        f"promoted to primary (reason={result.reason}, "
                        f"prior_source={result.prior_source or 'unknown'})"
                    )
                else:
                    print(
                        f"not promoted: {result.reason} "
                        f"(quorum {result.quorum_reachable}/{result.quorum_required}, "
                        f"primary_reachable={str(result.primary_reachable).lower()})"
                    )
                return 0 if result.promoted else 1
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.command == "health" and getattr(args, "health_command", None) == "agent-matrix":
        try:
            result = agent_matrix(config=args.config, timeout=args.matrix_timeout)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            for agent in result.agents:
                print(f"{agent.status} {agent.id} runtime={agent.runtime or '-'}")
                for probe in agent.endpoints:
                    print(f"  {probe.status} {probe.name} {probe.url or '-'} {probe.note}")
        return 0 if result.ok else 1

    if args.command == "health" and getattr(args, "health_command", None) == "daily-handoff":
        try:
            result = daily_handoff(state=args.state, date=args.date, actor=args.actor, config=args.config)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            for thread in result.created:
                print(f"created {thread.id} -> {thread.target} {thread.title}")
            for title in result.skipped:
                print(f"skipped {title}")
        return 0

    if args.command == "health" and getattr(args, "health_command", None) == "notify-check":
        try:
            result = notify_and_deliver(
                state=args.state,
                adapter=args.adapter,
                dedupe_window_minutes=args.dedupe_window_minutes,
                escalate_after_minutes=args.escalate_after_minutes,
                dry_run=args.dry_run,
                dashboard_url=args.dashboard_url,
                deliveries_path=args.deliveries,
                webhook_url_env=args.webhook_url_env,
                config=args.config,
                timeout=args.notify_timeout,
                quiet_stdout=args.json_output,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            for delivery in result.deliveries:
                if delivery.adapter != "stdout":
                    detail = f" {delivery.detail}" if delivery.detail else ""
                    print(f"{delivery.status} {delivery.kind} {delivery.thread_id}{detail}")
            print(
                f"candidates={len(result.candidates)} suppressed={len(result.suppressed)} "
                f"deliveries={len(result.deliveries)} adapter={result.adapter} "
                f"dry_run={result.dry_run} ok={result.ok}"
            )
        return 0 if result.ok else 1

    if args.command == "health":
        result = run_health(
            url=args.url,
            token=_env_value(args.auth_env),
            recall_question=args.recall_question,
            recall_project=args.recall_project,
            audit_log=args.audit_log,
            replica_vault=args.replica_vault,
            max_replica_age_minutes=args.max_replica_age_minutes,
            timeout=args.timeout,
        )
        if args.report_state is not None:
            message_id = report_failures_to_bus(state=args.report_state, result=result, host_label=args.host_label)
            if message_id and not args.json_output:
                print(f"alert posted to bus: {message_id}")
        if args.json_output:
            print(result.to_json())
        else:
            for check in result.checks:
                status = "PASS" if check.ok else "FAIL"
                print(f"{status} {check.name}")
        return 0 if result.ok else 1

    if args.command == "audit-log":
        if args.audit_log_command == "verify":
            result = verify_chain(args.log)
            if args.json_output:
                print(result.to_json())
            else:
                status = "intact" if result.ok else f"BROKEN at line {result.first_break_line}"
                print(f"audit log {status} events={result.events}")
            return 0 if result.ok else 1

    if args.command == "import":
        importers = {
            "markdown": import_markdown,
            "obsidian": import_obsidian,
            "basic-memory": import_basic_memory,
        }
        if args.import_command in importers:
            try:
                result = importers[args.import_command](
                    source=args.source,
                    vault=args.vault,
                    project=args.project,
                    dry_run=args.dry_run,
                )
            except FileNotFoundError as exc:
                print(f"error: source not found: {exc}", file=sys.stderr)
                return 1
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if args.json_output:
                print(result.to_json())
            else:
                print(f"imported={len(result.imported)} skipped={len(result.skipped)}")
            return 0

    if args.command == "bridge-policy":
        try:
            if args.output:
                result = write_bridge_policy(
                    profile=args.profile,
                    output=args.output,
                    upstream=args.upstream,
                    auth_env=args.auth_env,
                )
            else:
                result = build_bridge_policy(profile=args.profile, upstream=args.upstream, auth_env=args.auth_env)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            print(json.dumps(result.policy, indent=2, sort_keys=False))
        return 0

    if args.command == "digest":
        try:
            result = build_digest(
                state=args.state,
                vault=args.vault,
                agent=args.agent,
                window_hours=args.window_hours,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            label = "weekly review" if args.window_hours >= 168 else "brief"
            print(f"# {result.agent} {label} ({result.generated_at})")
            if result.session:
                print(f"\nSession state (updated {result.session['updated_at']}):\n  {result.session['content']}")
            print("\nFocus:")
            for line in result.focus:
                print(f"  - {line}")
            print(
                f"\nOpen tasks: {len(result.open_tasks)} ({len(result.overdue_tasks)} overdue) | "
                f"handoffs to you: {len(result.assigned_handoffs)} | "
                f"approvals awaiting: {len(result.awaiting_approvals)} | "
                f"alerts: {len(result.recent_alerts)} | "
                f"completed this window: tasks={result.completed['tasks']} handoffs={result.completed['handoffs']}"
            )
        return 0

    if args.command == "readiness":
        result = readiness(repo=args.repo)
        if args.json_output:
            print(result.to_json())
        else:
            print(f"Score: {result.score}%")
            print(f"Structural checklist complete: {'yes' if result.structural_complete else 'no'}")
            for item in result.items:
                evidence = ", ".join(item.evidence) if item.evidence else "no evidence"
                print(f"- {item.status.upper()} {item.label}: {evidence}")
                if item.status != "complete":
                    print(f"  next: {item.next_step}")
        return 0 if result.score >= 90 else 1

    if args.command == "audit":
        result = run_audit(repo=args.repo, vault=args.vault)
        if args.json_output:
            print(result.to_json())
        else:
            print(f"Internal audit evidence: {'pass' if result.ok else 'fail'}")
            print(f"Public release blocked: {'yes' if result.public_release_blocked else 'no'}")
            for check in result.checks:
                status = "PASS" if check.ok else "FAIL"
                print(f"- {status} {check.label}")
                for finding in check.findings:
                    print(f"  finding: {finding}")
            for blocker in result.release_blockers:
                print(f"blocker: {blocker}")
        return 0 if result.ok else 1

    if args.command == "benchmark":
        if args.benchmark_command == "recall":
            try:
                result = run_recall_benchmark(
                    vault=args.vault,
                    cases_path=args.cases,
                    max_tokens=args.max_tokens,
                    retrieval_mode=args.retrieval_mode,
                )
            except (FileNotFoundError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if args.json_output:
                print(result.to_json())
            else:
                print(f"Recall benchmark: {result.passed}/{result.total} score={result.score}")
                for case in result.cases:
                    status = "PASS" if case.ok else "FAIL"
                    print(f"- {status} {case.id} confidence={case.confidence:.2f}")
                    for missing in case.missing_sources:
                        print(f"  missing: {missing}")
                    for forbidden in case.forbidden_hits:
                        print(f"  forbidden: {forbidden}")
            return 0 if result.ok else 1

    if args.command == "evidence":
        if args.evidence_command == "export":
            try:
                result = export_evidence(
                    repo=args.repo,
                    vault=args.vault,
                    benchmark_cases=args.benchmark_cases,
                    output=args.output,
                    run_docker=args.run_docker,
                    run_bridge=args.run_bridge,
                    mcp_client_evidence=args.mcp_client_evidence,
                )
            except (FileNotFoundError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            internal_ok = bool(result.audit["ok"]) and all(
                bool(item["ok"]) for item in result.recall_benchmarks.values()
            )
            if args.json_output:
                print(result.to_json())
            else:
                if args.output:
                    print(f"wrote {args.output}")
                print(f"git_head={result.git_head or 'unknown'}")
                print(f"release_blockers={len(result.release_blockers)}")
                print(f"internal_evidence={'pass' if internal_ok else 'fail'}")
            return 0 if internal_ok else 1
        if args.evidence_command == "mcp-client":
            try:
                payload = generate_mcp_client_evidence(vault=args.vault, client=args.client, output=args.output)
                validation = validate_mcp_client_evidence(args.output) if args.output else {"ok": True, "errors": []}
            except (FileNotFoundError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            result = {"ok": bool(validation["ok"]), "evidence": payload, "validation": validation}
            if args.json_output:
                print(json.dumps(result, sort_keys=True))
            else:
                if args.output:
                    print(f"wrote {args.output}")
                print(f"ok={'yes' if validation['ok'] else 'no'}")
                for error in validation["errors"]:
                    print(f"error: {error}")
            return 0 if validation["ok"] else 1
        if args.evidence_command == "sign":
            try:
                payload = attest_evidence_file(args.evidence, key_path=args.key, principal=args.principal)
            except (FileNotFoundError, ValueError, AttestationError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            attestation = payload.get("attestation", {})
            if args.json_output:
                print(json.dumps({"ok": True, "attestation": attestation}, sort_keys=True))
            else:
                print(f"signed {args.evidence} as principal={args.principal}")
            return 0

    if args.command == "release-candidate":
        try:
            result = release_candidate_report(
                repo=args.repo,
                vault=args.vault,
                benchmark_cases=args.benchmark_cases,
                run_docker=args.run_docker,
                run_bridge=args.run_bridge,
                mcp_client_evidence=args.mcp_client_evidence,
                require_provenance=args.require_provenance,
                provenance_dir=args.provenance_dir,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.json_output:
            print(result.to_json())
        else:
            print(result.summary)
            print(f"private_preview_allowed={'yes' if result.private_preview_allowed else 'no'}")
            print(f"public_release_allowed={'yes' if result.public_release_allowed else 'no'}")
            for blocker in result.internal_evidence_blockers:
                print(f"internal_blocker: {blocker}")
            for blocker in result.public_release_blockers:
                print(f"public_release_blocker: {blocker}")
            for action in result.next_actions:
                print(f"next: {action}")
        return 0 if result.private_preview_allowed else 1

    if args.command == "release-host":
        result = release_host_report(
            repo=args.repo,
            run_docker=args.run_docker,
            run_bridge=args.run_bridge,
            mcp_client_evidence=args.mcp_client_evidence,
            require_provenance=args.require_provenance,
            provenance_dir=args.provenance_dir,
        )
        if args.json_output:
            print(result.to_json())
        else:
            print(f"Release-host evidence: {'complete' if result.public_release_ready else 'blocked'}")
            for check in result.checks:
                print(f"- {check.status.upper()} {check.label}")
                for item in check.evidence:
                    print(f"  evidence: {item}")
                if check.status != "complete":
                    print(f"  next: {check.next_step}")
        return 0 if result.ok else 1

    if args.command == "attest":
        return _run_attest(args)

    if args.command == "dogfood":
        if args.dogfood_command == "self":
            result = dogfood_self(
                repo=args.repo,
                run_docker=args.run_docker,
                run_bridge=args.run_bridge,
                mcp_client_evidence=args.mcp_client_evidence,
            )
        elif args.dogfood_command == "live-api":
            result = dogfood_live_api(vault=args.vault)
        else:
            return 2
        if args.json_output:
            print(result.to_json())
        else:
            for check in result.checks:
                status = "PASS" if check.ok else "FAIL"
                print(f"{status} {check.name}")
        return 0 if result.ok else 1

    return 2


def _env_value(name: str | None) -> str | None:
    if not name:
        return None
    return os.environ.get(name)


def _validated_bearer_secret(value: str | None, *, source: str) -> str | None:
    if value is None:
        return None
    if not re.fullmatch(r"[!-~]{32,4096}", value):
        raise ValueError(f"{source} must contain one 32-4096 character printable ASCII bearer token")
    return value


def _credential_value(*, auth_env: str | None, auth_file: Path | None) -> str | None:
    if auth_env and auth_file is not None:
        raise ValueError("--auth-env and --auth-file are mutually exclusive")
    if auth_file is None:
        return _validated_bearer_secret(_env_value(auth_env), source="auth environment variable")
    if auth_file.is_symlink() or not auth_file.is_file():
        raise ValueError("auth file must be a regular non-symlink file")
    try:
        raw = auth_file.read_bytes()
        if len(raw) > 4096:
            raise ValueError("auth file is too large")
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("auth file is unreadable") from exc
    value = text.strip()
    encoded = value.encode("utf-8")
    if not value or raw not in {encoded, encoded + b"\n"}:
        raise ValueError("auth file must contain exactly one token line")
    return _validated_bearer_secret(value, source="auth file")


def _bearer_header(name: str | None) -> str | None:
    value = _validated_bearer_secret(_env_value(name), source="bearer environment variable")
    if not value:
        return None
    return f"Bearer {value}"


@boundary("worker")
def _run_execution_worker(args: argparse.Namespace) -> int:
    """One execution-worker tick, plus its liveness record.

    The record is written in ``finally`` so a tick that refused its
    configuration or crashed still says so; telemetry failures are swallowed
    by ``write_tick_record`` and never change the tick's exit code.
    """
    tick: dict[str, str] = {"result": "error", "detail": "tick did not finish"}
    try:
        return _execution_worker_tick(args, tick)
    finally:
        write_tick_record(
            args.state,
            component=WORKER_COMPONENT,
            result=tick["result"],
            detail=tick["detail"],
            route_revision=tick.get("route_revision", ""),
            route_sha256=tick.get("route_sha256", ""),
        )


def _execution_worker_tick(args: argparse.Namespace, tick: dict[str, str]) -> int:
    try:
        route_document = load_route_document(args.routes)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        tick["detail"] = f"invalid execution routes: {exc}"
        print(f"error: invalid execution routes: {exc}", file=sys.stderr)
        return 2
    routes = route_document.routes
    route_attestation = {
        "route_revision": route_document.revision,
        "route_sha256": route_document.attested_sha256,
    }
    tick.update(route_attestation)
    route_errors = validate_routes(routes, environ=os.environ)
    if not routes or route_errors:
        detail = "; ".join(route_errors) if route_errors else "no execution routes configured"
        tick["detail"] = detail
        print(f"error: {detail}", file=sys.stderr)
        return 2
    required_lease = max(route.timeout_seconds for route in routes.values()) + 2
    if args.lease_seconds < required_lease:
        tick["detail"] = f"lease_seconds below {required_lease}"
        print(
            f"error: lease_seconds must be at least {required_lease} for configured route timeouts",
            file=sys.stderr,
        )
        return 2
    # First-heartbeat window: validated before any claim so a bad budget
    # never strands a leased attempt. The default never undercuts a longer
    # renewal lease, so an existing --lease-seconds keeps working as-is.
    if args.first_heartbeat_seconds is None:
        first_heartbeat_seconds = max(DEFAULT_FIRST_HEARTBEAT_SECONDS, args.lease_seconds)
    else:
        first_heartbeat_seconds = args.first_heartbeat_seconds
        if first_heartbeat_seconds < args.lease_seconds:
            tick["detail"] = "first_heartbeat_seconds below lease_seconds"
            print(
                "error: first_heartbeat_seconds must be at least lease_seconds "
                f"({args.lease_seconds})",
                file=sys.stderr,
            )
            return 2
    if first_heartbeat_seconds > MAX_LEASE_SECONDS:
        tick["detail"] = f"first_heartbeat_seconds above {MAX_LEASE_SECONDS}"
        print(
            f"error: first_heartbeat_seconds must be at most {MAX_LEASE_SECONDS}",
            file=sys.stderr,
        )
        return 2
    capable = set(routes)
    from datetime import datetime
    now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else None
    try:
        execution = claim_execution(
            args.state, worker=args.worker, execution_capable_targets=capable, now=now,
            lease_seconds=args.lease_seconds, max_attempts=args.max_attempts,
            execution_id=getattr(args, "execution_id", None),
            subject_id=getattr(args, "subject_id", None), target=getattr(args, "target", None),
        )
    except ValueError as exc:
        tick["detail"] = f"execution claim refused: {exc}"
        print(f"error: {tick['detail']}", file=sys.stderr)
        return 2
    if execution is None:
        tick.update(result="idle", detail="no claimable execution")
        result = {"status": "idle", **route_attestation}
        print(json.dumps(result, sort_keys=True) if args.json_output else result)
        return 0
    try:
        # The wake's delivery record is persisted before network I/O so
        # the delivery ID it names always resolves for its target.
        delivery = deliver_execution_attempt(
            execution, routes[execution.target], now=now, lease_seconds=args.lease_seconds,
            state=args.state, first_heartbeat_seconds=first_heartbeat_seconds,
        )
        if not delivery.accepted:
            raise RuntimeError(delivery.detail)
        # The accepted wake opens the attempt's first-heartbeat window; the
        # target's identity-bound heartbeats then renew by lease_seconds.
        heartbeat_execution(
            args.state, execution_id=execution.id, attempt_id=execution.attempt_id,
            worker=args.worker, now=now, lease_seconds=args.lease_seconds,
            detail=json.dumps(delivery.to_dict(), sort_keys=True),
            first_heartbeat_seconds=first_heartbeat_seconds,
        )
        tick.update(result="ok", detail=f"leased {execution.id} target={execution.target}")
        result = {
            "status": "leased",
            "execution_id": execution.id,
            "attempt_id": execution.attempt_id,
            "delivery": delivery.to_dict(),
            **route_attestation,
        }
        print(json.dumps(result, sort_keys=True) if args.json_output else result)
        return 0
    except (RuntimeError, ValueError, OSError) as exc:
        capture(exc, component="worker", code="wake_failure", expected=isinstance(exc, ValueError))
        finalized = record_execution_failure(
            args.state, execution_id=execution.id, attempt_id=execution.attempt_id,
            worker=args.worker, detail=str(exc), now=now
        )
        if finalized.status == "completed":
            tick.update(result="ok", detail=f"completed {execution.id} target={execution.target}")
            result = {
                "status": "completed",
                "execution_id": execution.id,
                "terminal_event_id": finalized.terminal_event_id,
                **route_attestation,
            }
            print(json.dumps(result, sort_keys=True) if args.json_output else result)
            return 0
        tick.update(result="error", detail=f"wake failed for {execution.id} target={execution.target}: {exc}")
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_routes_command(args: argparse.Namespace) -> int:
    if args.routes_command == "seal":
        return _run_routes_seal(args)
    return _run_routes_doctor(args)


def _run_routes_seal(args: argparse.Namespace) -> int:
    """Write the versioned route document. Never resolves or prints a secret.

    Exit codes: 2 for a refused or invalid seal, 0 otherwise.
    """
    if args.in_place and args.out is not None:
        message = "exactly one of --out or --in-place is required"
        if args.json_output:
            print(json.dumps({"ok": False, "error": message}, sort_keys=True))
        else:
            print(f"error: {message}", file=sys.stderr)
        return 2
    if not args.dry_run and not args.in_place and args.out is None:
        message = "exactly one of --out or --in-place is required"
        if args.json_output:
            print(json.dumps({"ok": False, "error": message}, sort_keys=True))
        else:
            print(f"error: {message}", file=sys.stderr)
        return 2
    try:
        report = seal_route_document(
            args.routes,
            revision=args.revision,
            owner=args.owner,
            approved_at=args.approved_at,
            destination=None if args.in_place else args.out,
            dry_run=args.dry_run,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if args.json_output:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json_output:
        print(json.dumps(report, sort_keys=True))
    else:
        verb = "planned" if report["dry_run"] else "sealed"
        targets = report["targets"]
        count = len(targets) if isinstance(targets, list) else 0
        unresolved = report["unresolved_references"]
        unresolved_count = len(unresolved) if isinstance(unresolved, list) else 0
        print(
            f"{verb} revision={report['revision']} owner={report['owner']} "
            f"routes={count} sha256={report['sha256']} "
            f"unresolved_references={unresolved_count}"
        )
        for reference in unresolved if isinstance(unresolved, list) else []:
            print(f"  unresolved: {reference}")
    return 0


def _run_routes_doctor(args: argparse.Namespace) -> int:
    """Validate the route document and report per-route status without secrets.

    Exit codes: 2 for an unloadable/invalid document, 1 for per-route
    validation errors, 0 otherwise. Probe failures are operational, not
    configuration, and never change the exit code on their own.
    """
    try:
        document = load_route_document(args.routes)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if args.json_output:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    environ = os.environ
    validation_errors = validate_routes(document.routes, environ=environ)
    document_report: dict[str, object] = {
        "sha256": document.sha256,
        "versioned": document.versioned,
        "schema": document.schema or "unversioned",
        "revision": document.revision or "unversioned",
        "approved_at": document.approved_at or "unversioned",
        "owner": document.owner or "unversioned",
    }
    if document.previous_revision:
        document_report["previous"] = {
            "revision": document.previous_revision,
            "sha256": document.previous_sha256,
        }
    routes_report: dict[str, dict[str, object]] = {}
    for target, route in sorted(document.routes.items()):
        entry: dict[str, object] = {
            "runtime": route.runtime,
            "timeout_seconds": route.timeout_seconds,
            "url_env": route.url_env,
            "url_env_present": bool(environ.get(route.url_env, "").strip()),
            "credential_env": route.credential_env,
            "credential_env_present": bool(environ.get(route.credential_env, "").strip()),
        }
        if args.probe:
            entry["probe"] = _probe_route_endpoint(environ.get(route.url_env, "").strip(), route.timeout_seconds)
        routes_report[target] = entry
    report: dict[str, object] = {
        "ok": not validation_errors,
        "document": document_report,
        "validation_errors": validation_errors,
        "routes": routes_report,
    }
    if args.json_output:
        print(json.dumps(report, sort_keys=True))
    else:
        status = "OK" if not validation_errors else "FAIL"
        print(f"{status} routes={len(document.routes)} sha256={document.sha256}")
        print(
            f"schema={document_report['schema']} revision={document_report['revision']} "
            f"approved_at={document_report['approved_at']} owner={document_report['owner']}"
        )
        if document.previous_revision:
            print(f"previous revision={document.previous_revision} sha256={document.previous_sha256}")
        for target, entry in routes_report.items():
            url_state = "present" if entry["url_env_present"] else "missing"
            credential_state = "present" if entry["credential_env_present"] else "missing"
            line = (
                f"route {target} runtime={entry['runtime']} timeout={entry['timeout_seconds']}s "
                f"url_env={entry['url_env']}({url_state}) "
                f"credential_env={entry['credential_env']}({credential_state})"
            )
            probe = entry.get("probe")
            if isinstance(probe, dict):
                probe_state = "ok" if probe["ok"] else f"fail({probe.get('detail', '')})"
                line += f" probe={probe['endpoint'] or 'unresolved'} {probe_state}"
            print(line)
        for error in validation_errors:
            print(f"ERROR {error}")
    return 0 if not validation_errors else 1


def _probe_route_endpoint(url: str, timeout_seconds: int) -> dict[str, object]:
    """Bounded TCP connect to the route endpoint's host:port.

    Never reports the URL itself (it may embed tokens); only hostname:port and
    a connect ok/fail with the exception class name. The implementation is
    shared with ``arvyx delivery probe`` so both surfaces agree.
    """
    return probe_route_endpoint(url, timeout_seconds)


def _prepare_default_paths(args: argparse.Namespace) -> None:
    if hasattr(args, "vault"):
        args.vault = resolve_default_vault(args.vault)
    if hasattr(args, "cases"):
        args.cases = resolve_default_benchmark_cases(args.cases)
    if hasattr(args, "benchmark_cases"):
        args.benchmark_cases = resolve_default_benchmark_cases(args.benchmark_cases)
    if _requires_repo_checkout(args):
        args.repo = ensure_repo_checkout(args.repo)


def _requires_repo_checkout(args: argparse.Namespace) -> bool:
    if args.command == "evidence":
        return args.evidence_command == "export"
    if args.command in {"release-candidate", "release-host"}:
        return True
    if args.command == "dogfood" and args.dogfood_command == "self":
        return True
    return False


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_attest(args: argparse.Namespace) -> int:
    if args.attest_command == "provenance":
        tree = git_tree_sha(args.repo)
        if tree is None:
            print("error: --repo must be a git checkout to bind provenance to a tree", file=sys.stderr)
            return 1
        payload: dict[str, object] = {
            "schema_version": 1,
            "check_id": args.check,
            "git_tree": tree,
            "result": args.result,
            "workflow": args.workflow,
            "ran_at": _now_iso(),
        }
        try:
            payload["attestation"] = sign_payload(
                payload, key_path=args.key, principal=args.principal, namespace=NS_RUN_PROVENANCE
            )
        except (FileNotFoundError, ValueError, AttestationError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if args.json_output:
            print(json.dumps({"ok": True, "check_id": args.check, "output": str(args.output)}, sort_keys=True))
        else:
            print(f"signed {args.check} provenance -> {args.output}")
        return 0

    if args.attest_command == "model-review":
        try:
            path = validate_model_review_receipt_path(
                args.repo, args.output or model_review_attestation_path(args.repo, args.subject)
            )
        except AttestationError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        tree = git_tree_sha(args.repo)
        if tree is None:
            print("error: --repo must be a git checkout to bind the model review to a tree", file=sys.stderr)
            return 1
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"error: invalid model-review receipt {path}: {exc}", file=sys.stderr)
                return 1
            if (
                not isinstance(payload, dict)
                or payload.get("subject") != args.subject
                or payload.get("artifact_git_tree") != tree
                or payload.get("policy_version") != MODEL_REVIEW_POLICY
                or payload.get("custody") != MODEL_REVIEW_CUSTODY
                or not isinstance(payload.get("reviews"), list)
            ):
                print(f"error: {path} is not a {args.subject} attestation", file=sys.stderr)
                return 1
        else:
            payload = {
                "schema_version": 1,
                "subject": args.subject,
                "status": "pending",
                "artifact_git_tree": tree,
                "policy_version": MODEL_REVIEW_POLICY,
                "custody": MODEL_REVIEW_CUSTODY,
                "reviews": [],
            }
        try:
            entry = model_review_entry(
                repo=args.repo,
                provider=args.provider,
                model=args.model,
                verdict=args.verdict,
                reviewed_at=_now_iso(),
                scope=args.scope,
                report_path=args.report,
            )
        except (FileNotFoundError, ValueError, AttestationError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        existing_reviews = payload.get("reviews")
        reviews = list(existing_reviews) if isinstance(existing_reviews, list) else []
        if any(isinstance(item, dict) and item.get("reviewer_id") == entry["reviewer_id"] for item in reviews):
            print(f"error: review from {entry['reviewer_id']} already exists", file=sys.stderr)
            return 1
        reviews.append(entry)
        payload["reviews"] = reviews
        payload["status"] = "pending"
        payload.pop("synthesis", None)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if args.json_output:
            print(json.dumps({"ok": True, "subject": args.subject, "models": len(reviews), "output": str(path)}, sort_keys=True))
        else:
            print(f"{args.subject}: {len(reviews)} model review(s) -> {path}")
        return 0

    if args.attest_command == "model-synthesis":
        try:
            path = validate_model_review_receipt_path(
                args.repo, args.output or model_review_attestation_path(args.repo, args.subject)
            )
        except AttestationError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if not path.is_file():
            print(f"error: no model reviews to synthesize: {path}", file=sys.stderr)
            return 1
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: invalid model-review receipt {path}: {exc}", file=sys.stderr)
            return 1
        tree = git_tree_sha(args.repo)
        if (
            not isinstance(payload, dict)
            or payload.get("subject") != args.subject
            or tree is None
            or payload.get("artifact_git_tree") != tree
            or payload.get("policy_version") != MODEL_REVIEW_POLICY
            or payload.get("custody") != MODEL_REVIEW_CUSTODY
        ):
            print(f"error: {path} is not a current {args.subject} model-review attestation", file=sys.stderr)
            return 1
        payload["status"] = "complete"
        payload["custody"] = MODEL_REVIEW_CUSTODY
        payload["synthesis"] = {
            "decision": args.decision,
            "synthesizer": args.synthesizer,
            "synthesized_at": _now_iso(),
            "agreements": args.agreement,
            "disagreements": args.disagreement,
            "resolution": args.resolution,
        }
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if args.json_output:
            print(json.dumps({"ok": True, "subject": args.subject, "decision": args.decision, "output": str(path)}, sort_keys=True))
        else:
            print(f"{args.subject}: synthesis={args.decision} -> {path}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
