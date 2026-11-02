from __future__ import annotations

import ast
import codecs
from bisect import bisect_right
import subprocess
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit


SOURCE_SKIP_DIRS = frozenset({'.git', '__pycache__', '.pytest_cache', '.ruff_cache',
    '.venv', '.arvyx', 'build', 'dist', 'htmlcov', 'node_modules'})


def iter_source_files(root):
    """Tracked + unignored candidate source; lockfiles/vendor remain scanned.

    Installed node_modules are a separate dependency assurance boundary. In an
    extracted source tree prune directories before descent, never after rglob.
    """
    root = Path(root)
    if (root / '.git').exists():
        try:
            tracked = subprocess.run(['git', '-C', str(root), 'ls-files', '--cached', '-z'],
                check=True, capture_output=True, timeout=10)
            result = subprocess.run(['git', '-C', str(root), 'ls-files', '--others',
                '--exclude-standard', '-z'], check=True, capture_output=True, timeout=10)
        except subprocess.SubprocessError as exc:
            raise ValueError('source enumeration unavailable or deadline exceeded') from exc
        tracked_names = set(tracked.stdout.decode('utf-8', errors='surrogateescape').split('\0')) - {''}
        names = set(result.stdout.decode('utf-8', errors='surrogateescape').split('\0')) - {''}
        names.update(tracked_names)
        if len(names) > 50000 or len(tracked.stdout) + len(result.stdout) > 8 * 1024 * 1024:
            raise ValueError('source enumeration inventory budget exceeded')
        for name in sorted(names):
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name:
                raise ValueError('invalid source inventory path')
            path = root / name
            parts = relative.parts
            # Pruning is only for untracked dependency/output trees. Tracked
            # release inputs are never exempt because of a directory basename.
            if name not in tracked_names and any(p in SOURCE_SKIP_DIRS or p.endswith('.egg-info') for p in parts):
                continue
            if path.is_file():
                yield path
    else:
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SOURCE_SKIP_DIRS and not d.endswith('.egg-info'))
            for name in sorted(files):
                path = Path(directory) / name
                if path.is_file():
                    yield path


def is_http_url(url: str) -> bool:
    """True for an http(s) URL. Single source of truth for the outbound-URL
    allowlist: every urlopen call site gates on this so a misconfigured
    file:// / gopher:// endpoint cannot exfiltrate local files (SSRF), and
    the allowed scheme set can never drift between call sites."""
    return urlsplit(url).scheme.lower() in ("http", "https")


# The company domain is a reviewed identifier; every detector derives its regex
# from this one plain spelling instead of repeating escaped copies.
_COMPANY_DOMAIN = "arven.digital"
_COMPANY_DOMAIN_RE = re.escape(_COMPANY_DOMAIN)
# Pre-rename hidden state namespace (quarantined, never created); derived so the
# retired word is written once, in the reviewed domain above.
_LEGACY_NAMESPACE = "." + _COMPANY_DOMAIN.split(".")[0]
_PRIVATE_EMAIL_PATTERN = rf"\b[A-Z0-9._%+-]+@{_COMPANY_DOMAIN_RE}\b"

_JWT_PATTERN = r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"

_POSTGRES_PATTERN = r"\bpostgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/[^\s'\"]+"

SECRET_PATTERNS = (
    # auth.issue_token: path-safe 1..64 character agent ID and token_hex(20).
    r"(?<![A-Za-z0-9_-])arv_[a-z0-9][a-z0-9_-]{0,63}_[0-9a-f]{40}(?![A-Za-z0-9_-])",
    r"sk-[A-Za-z0-9_-]{20,}",
    r"ghp_[A-Za-z0-9_]{20,}",
    r"github_pat_[A-Za-z0-9_]+",
    r"gh[oupsr]_[A-Za-z0-9_]{20,}",
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"npm_[A-Za-z0-9]{20,}",
    r"pypi-[A-Za-z0-9_-]{20,}",
    r"vcp_[A-Za-z0-9_-]{16,}",
    r"sntryu_[A-Za-z0-9_-]{16,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}",
    r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b",
    r"sk_(?:live|test)_[A-Za-z0-9]{16,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\baws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{35,}",
    r"\bAIza[0-9A-Za-z_-]{35}\b",
    _POSTGRES_PATTERN,
    _PRIVATE_EMAIL_PATTERN,
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    r"Bearer\s+[A-Za-z0-9._-]{16,}",
    r"BEGIN\s+(RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY",
    # key/token/password/secret assignment to a literal value. The call-shape
    # exemption (an unquoted identifier followed by an opening paren, e.g. a
    # helper call) applies ONLY to the unquoted branch: a quoted literal is
    # never a function call, so a quoted value with a trailing paren must still
    # be caught instead of slipping through on that trailing character. The
    # exemption also requires the paren to touch the identifier: whitespace
    # before the paren means the parenthesised text is prose about a literal
    # value, not a call, so that shape must be caught too.
    r"\b(api[_-]?key|token|password|secret)\s*[:=]\s*(?:['\"][^'\"\s]{8,}['\"]|(?![A-Za-z_][A-Za-z0-9_.]*\()[A-Za-z0-9._/!@#$%^&*+=?-]{8,})",
)

SECRET_RE = re.compile("(" + "|".join(SECRET_PATTERNS) + ")", re.IGNORECASE)

# The unanchored email local part can retry quadratically at every dotted
# word boundary. It cannot match without this suffix. Keep the same Unicode
# IGNORECASE semantics, and retain every other detector in the absent branch.
_PRIVATE_EMAIL_SUFFIX_RE = re.compile(rf"@{_COMPANY_DOMAIN_RE}\b", re.IGNORECASE)
_EMAIL_LOCAL_CHAR_RE = re.compile(r"[A-Z0-9._%+-]", re.IGNORECASE)
_WORD_RE = re.compile(r"\w")
_NON_EMAIL_SECRET_RE = re.compile(
    "(" + "|".join(p for p in SECRET_PATTERNS
                    if p not in {_PRIVATE_EMAIL_PATTERN, _POSTGRES_PATTERN, _JWT_PATTERN}) + ")",
    re.IGNORECASE,
)


def _postgres_spans(text: str, flags=re.IGNORECASE):
    """Index delimiters once instead of rescanning each prefix's suffix.

    Candidate lookups cost O(log n); successful regex matches consume disjoint
    spans. The original pattern still defines the accepted credential grammar.
    """
    prefixes = re.compile(r"\bpostgres(?:ql)?://", flags)
    candidates = prefixes.finditer(text)
    ats = [m.start() for m in re.finditer('@', text)]
    if not ats:
        return
    spaces = [m.start() for m in re.finditer(r'\s', text, flags)] + [len(text)]
    slashes = [m.start() for m in re.finditer('/', text)] + [len(text)]
    username = re.compile(r'[^:\s]+:', flags)
    detector = re.compile(_POSTGRES_PATTERN, flags)
    consumed = 0
    for prefix in candidates:
        if prefix.start() < consumed:
            continue
        user = username.match(text, prefix.end())
        if user is None:
            continue
        password = user.end()
        index = bisect_right(ats, password)
        if index == len(ats):
            continue
        at = ats[index]
        space = spaces[bisect_right(spaces, password - 1)]
        slash = slashes[bisect_right(slashes, at)]
        # An @ at password start means an empty password, not a later @.
        if (text[password:password + 1] == '@' or at >= space
                or slash <= at + 1 or slash >= space
                or slash + 1 >= len(text) or text[slash + 1] in "'\""
                or text[slash + 1].isspace()):
            continue
        match = detector.match(text, prefix.start())
        if match:
            consumed = match.end()
            yield match.span()


def _jwt_spans(text: str, flags=re.IGNORECASE):
    """Tokenize once; try the original grammar once per eligible segment.

    Repeated eyJ prefixes in a dotless run cannot trigger repeated suffix
    scans. Successful matches consume disjoint spans; failed triples scan
    at most three runs, preserving Unicode boundaries and IGNORECASE.
    """
    runs = list(re.finditer(r"[A-Za-z0-9_-]+", text, flags))
    prefix = re.compile(r"\beyJ(?=[A-Za-z0-9_-])", flags)
    detector = re.compile(_JWT_PATTERN, flags)
    consumed = 0
    for first, second, third in zip(runs, runs[1:], runs[2:]):
        if first.start() < consumed:
            continue
        if (text[first.end():second.start()] != '.'
                or text[second.end():third.start()] != '.'):
            continue
        candidate = prefix.search(text, first.start(), first.end())
        if candidate:
            match = detector.match(text, candidate.start())
            if match:
                consumed = match.end()
                yield match.span()


def canonical_secret_line_spans(text: str):
    """Map canonical full-text matches to inclusive source line ranges.

    Preserve offsets when masking sanctioned references. Multiline matches
    cannot inherit an exception granted to a different single source line.
    """
    masked = _SECRET_REF_RE.sub(
        lambda m: m.group(0) if _contains_secret_shape(m.group(1) + '/' + m.group(2))
        else re.sub(r"[^\r\n]", " ", m.group(0)), text)
    # Reuse the bounded union matcher, recording its exact character spans.
    spans = []
    bounded_secret_subn(masked, SECRET_RE, _spans=spans)
    boundaries = [m.end() for m in re.finditer(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]", text)]
    return {(bisect_right(boundaries, start) + 1,
             bisect_right(boundaries, end - 1) + 1) for start, end in spans}


def _contains_secret_shape(text: str) -> bool:
    if (_NON_EMAIL_SECRET_RE.search(text)
            or next(_jwt_spans(text), None) is not None
            or next(_postgres_spans(text), None) is not None):
        return True
    for suffix in _PRIVATE_EMAIL_SUFFIX_RE.finditer(text):
        end = suffix.start()
        start = end
        while start and _EMAIL_LOCAL_CHAR_RE.fullmatch(text[start - 1]):
            start -= 1
        # Preserve the original Unicode word-boundary and IGNORECASE semantics.
        for pos in range(start, end):
            if bool(_WORD_RE.fullmatch(text[pos])) != bool(pos and _WORD_RE.fullmatch(text[pos - 1])):
                return True
    return False

SECRET_REDACTION = "[REDACTED-SECRET]"

# secret://broker/path references are sanctioned pointers, not secrets:
# they carry no value, so they must survive redaction and are allowed in
# stored memory. Kept in sync with brokers.SECRET_REF_RE.
_SECRET_REF_RE = re.compile(r"secret://([a-z0-9][a-z0-9_-]{0,63})/([^\s'\"<>`]+)")


def private_key_block_spans(text):
    """Linear delimiter walk; an unmatched opening suppresses the remainder.

    A nested/mismatched delimiter cannot terminate an active private block.
    No repeated suffix searches or unbounded backtracking are used.
    """
    marker = re.compile(r"(?P<kind>BEGIN|END)\s+(?P<label>(?:(?:RSA|OPENSSH|EC|DSA|ENCRYPTED) )?PRIVATE KEY)(?:-----)?", re.IGNORECASE)
    start = None
    label = None
    for match in marker.finditer(text):
        if start is None and match['kind'].upper() == 'BEGIN':
            start = match.start()
            if text[max(0, start - 5):start] == '-----':
                start -= 5
            label = match['label'].upper()
        elif start is not None and match['kind'].upper() == 'BEGIN':
            # Nested openings are malformed: suppress through EOF.
            label = None
        elif start is not None and match['kind'].upper() == 'END' and match['label'].upper() == label:
            yield start, match.end()
            start = None
    if start is not None:
        yield start, len(text)


def suppress_private_key_blocks(text):
    """Keep line positions stable before source selection and clipping."""
    parts = []
    previous = 0
    for start, end in private_key_block_spans(text):
        # Count logical separators before deleting intervening text. Canonical
        # LF prevents a retained CR from merging with a later LF after deletion.
        separators = re.findall(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]", text[start:end])
        parts.extend((text[previous:start], '[REDACTED-SECRET]' + '\n' * len(separators)))
        previous = end
    parts.append(text[previous:])
    return ''.join(parts)


def bounded_secret_subn(text, detector, replacement="[REDACTED-SECRET]", *, _spans=None):
    """Find email runs once; redact the union of all canonical secret spans.

    Overlapping detector spans are conservatively redacted together, never
    exposing a suffix merely because another detector consumed its prefix.
    """
    email = _PRIVATE_EMAIL_PATTERN
    pattern = detector.pattern.replace(email, r"(?!)")
    has_postgres = _POSTGRES_PATTERN in pattern
    if has_postgres:
        pattern = pattern.replace(_POSTGRES_PATTERN, r"(?!)")
    has_jwt = _JWT_PATTERN in pattern
    if has_jwt:
        pattern = pattern.replace(_JWT_PATTERN, r"(?!)")
    non_email = re.compile(pattern, detector.flags)
    spans = [match.span() for match in non_email.finditer(text)]
    # Scanner line exceptions remain tied to the actual opening detector;
    # output consumers additionally suppress the entire block.
    if _spans is None:
        spans.extend(private_key_block_spans(text))
    if has_jwt:
        spans.extend(_jwt_spans(text, detector.flags))
    if has_postgres:
        spans.extend(_postgres_spans(text, detector.flags))
    local = re.compile(r"[A-Z0-9._%+-]", re.IGNORECASE)
    word = re.compile(r"\w")
    for suffix in _PRIVATE_EMAIL_SUFFIX_RE.finditer(text):
        start = suffix.start()
        while start and local.fullmatch(text[start - 1]):
            start -= 1
        for pos in range(start, suffix.start()):
            if bool(word.fullmatch(text[pos])) != bool(pos and word.fullmatch(text[pos - 1])):
                spans.append((pos, suffix.end()))
                break
    if _spans is not None:
        _spans.extend(spans)
    merged = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    parts = []
    previous = 0
    for start, end in merged:
        # Preserve every logical line separator consumed by a secret span.
        separators = "".join(re.findall(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]", text[start:end]))
        parts.extend((text[previous:start], replacement + separators))
        previous = end
    parts.append(text[previous:])
    return ''.join(parts), len(merged)


def redact_secrets(text: str) -> str:
    """Replace secret-shaped spans, preserving sanctioned secret refs."""
    text = suppress_private_key_blocks(text)
    stash: dict[str, str] = {}

    def protect(match: "re.Match[str]") -> str:
        if _contains_secret_shape(match.group(1) + '/' + match.group(2)):
            return match.group(0)
        key = f"\x00REF{len(stash)}\x00"
        stash[key] = match.group(0)
        return key

    protected = _SECRET_REF_RE.sub(protect, text)
    redacted, _ = bounded_secret_subn(protected, SECRET_RE, SECRET_REDACTION)
    for key, value in stash.items():
        redacted = redacted.replace(key, value)
    return redacted


def contains_literal_secret(text: str) -> bool:
    """True only for real secret material — sanctioned refs do not count."""
    return _contains_secret_shape(strip_secret_refs(text))


def strip_secret_refs(text: str) -> str:
    """Blank out sanctioned secret refs so only literal secrets remain."""
    return _SECRET_REF_RE.sub(
        lambda match: match.group(0) if _contains_secret_shape(match.group(1) + '/' + match.group(2)) else " ",
        text,
    )


DENYLIST_ENV = "ARVYX_PRIVATE_DENYLIST"
DENYLIST_RELATIVE = Path(".arvyx") / "private-denylist.txt"
SECRET_SCAN_ALLOWLIST_RELATIVE = Path("fixtures") / "secret-scan-allowlist.txt"
RELEASE_MANIFEST_RELATIVE = Path("config") / "public-release-paths.json"
RELEASE_CLASSIFICATIONS = frozenset({"private-only", "public-approved", "reimplemented-clean-room"})

TEXT_SUFFIXES = {
    ".bash", ".cfg", ".conf", ".css", ".env", ".example", ".html",
    ".ini", ".js", ".json", ".jsonl", ".md", ".py", ".sh", ".toml",
    ".ts", ".txt", ".yaml", ".yml",
}
TEXT_NAMES = {
    ".dockerignore", ".gitattributes", ".gitignore", "dockerfile", "license",
    "makefile", "notice",
}


def load_private_denylist(repo: Path | None = None) -> list[str]:
    """Load private-name deny terms from outside the tracked tree.

    The terms themselves are private context, so they must never be
    committed; they come from $ARVYX_PRIVATE_DENYLIST or the gitignored
    .arvyx/private-denylist.txt, one term per line, '#' comments allowed.
    """
    candidates: list[Path] = []
    env_path = os.environ.get(DENYLIST_ENV)
    if env_path:
        candidates.append(Path(env_path))
    elif repo is not None:
        candidates.append(repo / DENYLIST_RELATIVE)
    terms: list[str] = []
    for candidate in candidates:
        if not candidate.is_file():
            if env_path:
                raise ValueError("configured private denylist is not a regular file")
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            term = line.strip()
            if term and not term.startswith("#"):
                terms.append(term)
    if env_path and not terms:
        raise ValueError("configured private denylist has no terms")
    if not env_path and not terms:
        # The Arvyx rename was a clean break. A policy left at the pre-rename
        # location must not silently degrade the scan to an empty denylist.
        legacy = os.environ.get("ARVEN_PRIVATE_DENYLIST") or (
            repo is not None and (repo / _LEGACY_NAMESPACE / "private-denylist.txt").exists())
        if legacy:
            raise ValueError("private denylist found only at the pre-rename location; "
                             "move it to ARVYX_PRIVATE_DENYLIST or .arvyx/private-denylist.txt")
    return terms


def private_name_patterns(repo: Path | None = None, *, strict: bool = False) -> list[re.Pattern[str]]:
    """Compile private terms with boundaries plus common identity suffixes.

    A private term must not hide inside a longer identifier (for example a
    three-letter term inside an ordinary word). Common machine/agent suffixes
    and numeric variants remain blocked without reverting to noisy substring
    matching. Underscores and punctuation are treated as separators.
    """
    patterns: list[re.Pattern[str]] = []
    for term in load_private_denylist(repo):
        # Strict assurance requires loaded policy, not substring matching of
        # unrelated source vocabulary. Keep identity suffixes in both modes.
        patterns.append(_term_pattern(term))
    return patterns


_NAME_SUFFIX = r"(?:[-_. ]?(?:agent|assistant|bot|cli|host|machine|node|service|worker)|[0-9]+)?"


def _term_pattern(term: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![^\W_]){re.escape(term)}{_NAME_SUFFIX}(?![^\W_])", re.IGNORECASE)


# Reviewed product identifiers, not people or bare product words. Match exact
# lexical tokens only; do not exempt files, lines, arbitrary prefixes or keys.
_REVIEWED_PRODUCT_IDENTIFIERS = frozenset({
    'arvyx_control', 'arvyx-control', '.arvyx', 'arvyx_control_center_api',
    'arvyx-auth', 'arvyx-memory-wrapper', 'arven-memory-and-control',
    # External identities kept by the Arvyx rename (2026-10-30): repository/distribution
    # name, release-signing principals bound to docs/*signers.allowed, GitHub secret names.
    'arven-release-tooling-ci', 'arven-release-tooling-local',
    # Company identity (owner decision 2026-10-30): legal name, GitHub organization and
    # domain, exact forms only. Bare product/person words remain findings, and the
    # private e-mail detector still reports any address at the company domain.
    'Arven Digital', 'Arven-Digital', _COMPANY_DOMAIN, '.'.join(reversed(_COMPANY_DOMAIN.split('.'))),
    'arvyx-vault-format', 'arvyx-mcp-client-evidence', 'arvyx-run-provenance',
    'arvyx-memory-agent', 'arvyx-memory-operator', 'arvyx-memory-read-only',
    'arvyx-agent-delivery', 'arvyx-control-plane', 'arvyx-control-center',
    'arvyx-control-center-api', 'arvyx-control-api', 'arvyx-cockpit',
    'arvyx-cli', 'arvyx_dashboard_preferences', 'arvyx-decision-card-nonce',
    'arvyx-index-worker', 'arvyx-watchdog', 'arvyx-execution-worker',
    'arvyx-execution-watchdog', 'arvyx-benchmark-provenance',
    'ARVYX_PRIVATE_DENYLIST', 'ARVEN_PRIVATE_DENYLIST_B64',
    # Pre-rename technical identifiers kept for fail-closed legacy detection: the
    # retired environment variable, the quarantined state namespace, the legacy
    # distribution module name, and the escaped company domain as it appears
    # inside detector regex sources. Exact forms only; bare words stay findings.
    'ARVEN_PRIVATE_DENYLIST', *(f'{_LEGACY_NAMESPACE}{suffix}' for suffix in ('', '-replica', '-restored-candidate.json')),
    '.arvyx/' + _LEGACY_NAMESPACE, 'arven_memory_and_control',
    'ARVYX_PROJECTION_CACHE', 'ARVYX_AUTHORITY_STATE', 'ARVYX_EMBEDDINGS',
    'ARVEN_RELEASE_SIGNING_KEY', 'ARVYX_RELEASE_MIN_MODEL_REVIEWS',
    'ARVYX_RELEASE_BUILD_ID', 'ARVYX_SECRET_BROKERS', 'ARVYX_SECRET_DB',
    'ARVYX_MCP_TOKEN', 'ARVYX_AGENT_TOKEN', 'ARVYX_HERMES_TOKEN',
    'ARVYX_VAULT', 'ARVYX_PORT', 'ARVYX_CONTROL_SECRET_FILE',
    'ARVYX_CONTROL_SECRET', 'ARVYX_EXEC_URL', 'ARVYX_EXEC_SECRET',
    'ARVYX_ENABLE_OPERATOR_ARCHIVE', 'ARVYX_NOTIFY_WEBHOOK',
    'ARVYX_DIAGNOSTICS_DB', 'ARVYX_REPLICA_TOKEN',
    'ARVYX_AGENT_INTENTIONAL_HUMAN_TARGETS', 'ARVYX_AGENT_DELIVER_AFTER',
    'ARVYX_DECISION_CARD_TARGETS', 'ARVYX_DECISION_OPERATOR_USER_IDS',
    'ARVYX_WATCHDOG_ESCALATION_TARGET', 'ARVYX_TELEGRAM_BOT_TOKEN',
    'ARVYX_TELEGRAM_CHAT_ID', 'ARVYX_ALLOW_TELEGRAM_TEST_API_BASE',
    'ARVYX_DOGFOOD_AUTH', 'ARVYX_EDGE_OPERATOR_SECRET', 'ARVYX_EDGE_HOST',
    'ARVYX_EDGE_ORIGIN', 'ARVYX_MEMORY_LIMIT', 'ARVYX_CPU_LIMIT',
    'ARVYX_IMAGE', 'ARVYX_DOMAIN', 'ARVYX_DATA_VOLUME', 'ARVYX_DEPLOYMENT_ID',
    'ARVYX_BACKUP_AUTHORITY_ID', 'ARVYX_BACKUP_BINDING_KEY_FILE',
    'ARVYX_BACKUP_DIR', 'ARVYX_BACKUP_OFF_HOST', 'ARVYX_RESTORE_OPERATION_KEY',
    'ARVYX_TOKEN_EXPIRY_VAULT', 'ARVYX_TOKEN_EXPIRY_NOTIFY',
    'ARVYX_TEST_WEBHOOK', 'ARVYX_TEST_WEBHOOK_ABSENT',
    'ARVYX_TEST_TG_TOKEN', 'ARVYX_TEST_TG_CHAT',
    'ARVYX_TEST_AGENT_URL', 'ARVYX_TEST_AGENT_SECRET',
    'ARVYX_SECRET_TEST_SCREENSHOT', 'ARVYX_SECRET_TEST_PLAYWRIGHT',
    'ARVYX_SECRET_TEST_CHROMIUM', 'ARVYX_MISSING_URL', 'ARVYX_MISSING_SECRET',
})
# The hidden state namespace is reviewed only as a directory component, not
# as an arbitrary dotted personal name or longer path-component prefix.
_COMPANY_DOMAIN_REVERSED_RE = re.escape('.'.join(reversed(_COMPANY_DOMAIN.split('.'))))
_LEGACY_NAMESPACE_RE = re.escape(_LEGACY_NAMESPACE)
_PRODUCT_IDENTIFIER_RE = re.compile(
    rf'(?<![\w.@-])Arven Digital(?![\w-])|(?<![\w.-]){_COMPANY_DOMAIN_RE}(?![\w-]|\.\w)'
    rf'|(?<![\w.-]){_COMPANY_DOMAIN_REVERSED_RE}(?=\.)'
    # Legacy state namespace entries only as whole quoted literals in source (the
    # fail-closed quarantine list); an unquoted legacy path still carries whatever
    # personal context follows it and stays a finding.
    rf'''|(?<=["']){_LEGACY_NAMESPACE_RE}(?:-replica|-restored-candidate\.json)?(?=["'])'''
    rf'''|(?<=["'])\.arvyx/{_LEGACY_NAMESPACE_RE}(?=["'])'''
    r'|(?<!\w)\.arvyx(?=/)|\w+(?:-\w+)*')


_COMPANY_WORD_PATTERN = _term_pattern(_COMPANY_DOMAIN.split('.')[0]).pattern.casefold()


def contains_private_name(text: str, patterns: list[re.Pattern[str]]) -> bool:
    """A private term is a finding; only the company word is exempt inside a reviewed identifier.

    Reviewed identifiers are exact lexical tokens (company identity, product and
    retired technical names). The exemption covers the company word alone, so the
    organization's own repository, domain and legacy identifiers do not flag,
    while any other term, personal names included, stays a finding wherever it
    appears, even next to or inside a reviewed identifier.
    """
    if not patterns:
        return False
    reviewed_spans = [match.span() for match in _PRODUCT_IDENTIFIER_RE.finditer(text)
                      if match.group() in _REVIEWED_PRODUCT_IDENTIFIERS]
    reviewed_starts = [start for start, _ in reviewed_spans]
    for pattern in patterns:
        exemptable = pattern.pattern.casefold() == _COMPANY_WORD_PATTERN
        for match in pattern.finditer(text):
            index = bisect_right(reviewed_starts, match.start()) - 1
            if exemptable and index >= 0 and match.end() <= reviewed_spans[index][1]:
                continue
            return True
    return False


def private_name_exempt_paths(repo: Path) -> frozenset[str] | None:
    """Repository-relative paths the private-NAME detector may skip.

    Only paths the release manifest classifies ``private-only`` qualify: they
    are never exported, must carry the in-file do-not-publish notice, and are
    gated by scripts/public_release_boundary.py, so private names in them are
    expected rather than a leak. The secret-shape detector never uses this
    exemption and keeps scanning every file.

    Returns None when the manifest is missing, unreadable or malformed (bad
    version, non-string or unknown classification, invalid or duplicate path);
    callers must then name-scan every file (fail closed). Paths absent from
    the manifest, such as new untracked files, are never exempt.
    """
    def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key in release manifest")
        return dict(pairs)

    try:
        data = json.loads(
            (repo / RELEASE_MANIFEST_RELATIVE).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicates,
        )
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("paths"), dict):
        return None
    exempt: set[str] = set()
    for raw_path, classification in data["paths"].items():
        if not isinstance(classification, str) or classification not in RELEASE_CLASSIFICATIONS:
            return None
        normalized = PurePosixPath(raw_path).as_posix()
        if (
            normalized != raw_path
            or normalized in {"", "."}
            or normalized.startswith("/")
            or ".." in PurePosixPath(raw_path).parts
        ):
            return None
        if classification == "private-only":
            exempt.add(normalized)
    return frozenset(exempt)


def is_expected_text(path: Path) -> bool:
    return path.suffix.casefold() in TEXT_SUFFIXES or path.name.casefold() in TEXT_NAMES


IMAGE_MAGIC = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".webp": (b"RIFF",),
    ".gif": (b"GIF87a", b"GIF89a"),
}


# Exact maintained brand/evidence image bytes; not a general image validator.
_VERIFIED_IMAGE_DIGESTS = frozenset(['245de5223a33c8364c448d857a403ca303c31ca63136390412ec21720a4126a3', '53804960dd437eb56b8c36ecf9a305145ddd48509110fc7320b1fd68f41a44c1', '309bc460759fb28b8cbd58edd78fadca6525b2b3a0a46b5657ea84bee972bf9e', '5b401595d9b66ba19cc1b13daf1e2ec0e6c2a1954c089b1439ddc9cac0ccc0e4', '6666cf96f5461c2393594182aff846c4a759badd2bf1e4c67d5bb796e6f79ca6', '8ab4a894d5afff164ce409ecb81368ae899c1344bbe1c1de3b44c2275359fee7', '91a33a72b50b068c60b41606c4009a5213c5727bd2cf4959d5a6f70918b18800', '92dd3d139d69d4dc10e2a6e2266e3be70119415e4731555b8b86d24bc69f410e', 'b96b8546b8613f5ac6f12bb14b4f8b332b8cc1f30e06a98c1c501edde995cd12', 'cc5d373fea63d9e22f56ff9ecb39c867faf7b59ede35c187de4c5fdc75304b05', 'ce2265ab0c91e5a44faa9e48f5c13b321f453d92a8f341013051fdebe8fe89d2', 'df658b9f6cd77624581a44dfd18cdaa542496d97acde286d43761a652bd528f4', 'eae29a8f55af91017793af479ab19659b89f6a7c0b41cb7f6acbbbf4cb40be1e', 'f7ba1e637d7474f71182790e58f79f25f4376d736a92d0f5f5b3313e8ad7950d'])


def is_verified_image(path: Path) -> bool:
    """Only reviewed exact binary assets may skip text scanning.

    Magic is not evidence of safe bytes; appended/unknown image data fails closed.
    """
    magic_options = IMAGE_MAGIC.get(path.suffix.casefold())
    if not magic_options:
        return False
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    return (len(raw) >= 12 and any(raw.startswith(m) for m in magic_options)
            and hashlib.sha256(raw).hexdigest() in _VERIFIED_IMAGE_DIGESTS)


def is_verified_font(path: Path) -> bool:
    """Recognize only the two byte-pinned shipped Inter WOFF2 assets.

    Unknown or modified fonts remain decode-error findings, including payloads
    appended to otherwise valid font headers. Pins track the vendor inventory.
    """
    if path.suffix.casefold() != '.woff2':
        return False
    raw = path.read_bytes()
    return (len(raw) >= 48 and raw[:4] == b'wOF2'
            and int.from_bytes(raw[8:12], 'big') == len(raw)
            and hashlib.sha256(raw).hexdigest() in {
                'e564f652916db6c139570fefb9524a77c4d48f30c92928de9db19b6b5c7a262a',
                '693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3',
            })


def read_scannable_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16")
    if len(raw) >= 4 and len(raw) % 2 == 0:
        pairs = len(raw) // 2
        even_nuls = raw[0::2].count(0) / pairs
        odd_nuls = raw[1::2].count(0) / pairs
        if odd_nuls >= 0.30 and even_nuls <= 0.05:
            return raw.decode("utf-16-le")
        if even_nuls >= 0.30 and odd_nuls <= 0.05:
            return raw.decode("utf-16-be")
    text = raw.decode("utf-8-sig")
    if "\x00" in text:
        index = raw.find(b"\x00")
        raise UnicodeDecodeError("utf-8", raw, index, index + 1, "unexpected NUL in text")
    return text


def multiline_constant_secret_spans(text: str, *, max_lines: int = 8) -> set[tuple[int, int]]:
    """Find explicit cross-line concatenations of quoted string literals.

    Only adjacent literals joined by ``+`` or a backslash line continuation are
    assembled. Arbitrary punctuation is never stripped: regex definitions,
    YAML lists, documentation examples, and unrelated nearby strings therefore
    cannot synthesize a credential that was not present in the source.
    Python uses :func:`python_constant_secret_spans` instead.
    """
    literal_re = re.compile(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`',
        re.DOTALL,
    )
    # One newline index, no per-token prefix scans or suffix-list copies.
    newlines = [match.start() for match in re.finditer('\n', text)]
    tokens = list(literal_re.finditer(text))
    spans: set[tuple[int, int]] = set()
    runs = []
    run = []
    for token in tokens:
        if run and re.fullmatch(r"\s*(?:\+|\\)\s*", text[run[-1].end():token.start()]) is None:
            runs.append(run)
            run = []
        run.append(token)
    if run:
        runs.append(run)
    for run in runs:
        starts = [bisect_right(newlines, token.start()) + 1 for token in run]
        ends = [bisect_right(newlines, token.end()) + 1 for token in run]
        # Evaluate each line window once. Dense same-line concatenations do not
        # create one ever-growing scan for every token on that line.
        previous_line = None
        for index, token in enumerate(run):
            start_line = starts[index]
            if start_line == previous_line:
                continue
            previous_line = start_line
            end = bisect_right(ends, start_line + max_lines - 1)
            if end - index < 2:
                continue
            assembled = ''.join(run[i].group(0)[1:-1] for i in range(index, end))
            if contains_literal_secret(assembled):
                spans.add((start_line, ends[end - 1]))
    return spans


def python_constant_secret_spans(text: str) -> set[tuple[int, int]]:
    """Find secret-shaped values assembled entirely from Python literals."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    spans: set[tuple[int, int]] = set()
    values: dict[ast.AST, str | None] = {}
    pending: list[tuple[ast.AST, bool]] = [(tree, False)]
    remaining = 8 * 1024 * 1024
    while pending:
        node, visited = pending.pop()
        if not visited:
            pending.append((node, True))
            pending.extend((child, False) for child in ast.iter_child_nodes(node))
            continue
        value = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = values.get(node.left), values.get(node.right)
            if left is not None and right is not None:
                if len(left) + len(right) > remaining:
                    raise ValueError('constant-expression scan resource budget exceeded')
                value = left + right
        elif isinstance(node, ast.JoinedStr):
            parts = [values.get(child) for child in node.values]
            if all(part is not None for part in parts):
                strings = [part for part in parts if part is not None]
                if sum(map(len, strings)) > remaining:
                    raise ValueError('constant-expression scan resource budget exceeded')
                value = ''.join(strings)
        if value is not None:
            remaining -= len(value)
            if remaining < 0:
                raise ValueError('constant-expression scan resource budget exceeded')
        values[node] = value
        if value is None or not contains_literal_secret(value):
            continue
        spans.add((getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))))
    return spans


def secret_line_fingerprint(relative_path: Path, line: str) -> str:
    """Bind an allowed synthetic fixture to both its path and exact text."""
    material = relative_path.as_posix().encode("utf-8") + b"\0" + line.strip().encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def load_secret_scan_allowlist(repo: Path) -> set[str]:
    """Load reviewed synthetic-fixture fingerprints from the tracked tree."""
    path = repo / SECRET_SCAN_ALLOWLIST_RELATIVE
    if not path.is_file():
        return set()
    fingerprints: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip().lower()
        if not value or value.startswith("#"):
            continue
        if re.fullmatch(r"[0-9a-f]{64}", value):
            fingerprints.add(value)
    return fingerprints


def private_patterns(repo: Path | None = None) -> list[re.Pattern[str]]:
    return [*private_name_patterns(repo), SECRET_RE]


# JSON nesting is a product limit, not an interpreter accident. Python 3.11 raised
# RecursionError for a few hundred nested arrays; 3.12 and later parse thousands of
# levels. Every network and loopback intake (HTTP bodies of the API, the onboarding
# API, the control room, the external API and the external presentation, MCP stdio
# lines, owner-socket frames, pairing messages, remote effect fence requests and
# responses, secret-delivery target and JWKS responses, delivery receipts, replica
# stream lines and replies, broker health replies, remote embedding responses) and
# the projection checkpoint check this bound before parsing
# and report the same refusal on every supported interpreter. Readers of local,
# operator-owned files and SQLite rows keep RecursionError handling instead.
MAX_JSON_NESTING = 256


class JSONNestingError(json.JSONDecodeError):
    """Raised before parsing when a JSON text nests deeper than MAX_JSON_NESTING.

    A ``JSONDecodeError`` (hence a ``ValueError``) so that every existing decode
    handler, whichever of the two it catches, treats over-deep input as a refusal.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, "", 0)

    def __str__(self) -> str:
        # JSONDecodeError would append "line 1 column 1 (char 0)" from the empty
        # document; the bound has no position, so the message stands alone.
        return self.msg


def json_nesting_depth(text: str, *, limit: int = MAX_JSON_NESTING) -> int:
    """Return the maximum bracket nesting of ``text`` (strings and escapes ignored).

    Stops counting at ``limit + 1`` so an adversarial document costs one linear pass
    and no memory beyond a counter.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > limit:
                    return deepest
        elif char in "]}":
            depth -= 1 if depth else 0
    return deepest


def bounded_json_loads(text: str | bytes, *, limit: int = MAX_JSON_NESTING, **kwargs):
    """``json.loads`` with the explicit nesting bound applied first.

    Bytes are decoded as UTF-8 before scanning (a decoding error propagates as
    ``UnicodeDecodeError``, as it would from ``json.loads``); keyword arguments such
    as ``object_pairs_hook`` are passed through.
    """
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8")
    if json_nesting_depth(text, limit=limit) > limit:
        raise JSONNestingError(f"JSON nesting exceeds the limit of {limit}")
    try:
        return json.loads(text, **kwargs)
    except RecursionError as exc:  # interpreter bound below ours: same contract
        raise JSONNestingError("JSON nesting exceeds parser limit") from exc
