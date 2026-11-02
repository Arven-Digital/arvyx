"""Native launch plans; never infer conversation identity from terminal text.

Modified Python adaptation of Herdr src/agent_resume.rs (Apache-2.0),
5bd900d88c80d95f5b145397e45bbeea398b8165: exact ID and argv plans.
Unlike upstream shell-typed commands, AMC uses execve argument arrays.
"""
import re
import sys


def resume_plan(tool, conversation):
    if not isinstance(conversation, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,511}', conversation):
        raise ValueError('invalid exact native conversation ID')
    if tool not in {'claude', 'codex', 'hermes', 'gemini', 'fixture'}:
        raise ValueError('unsupported native tool; explicit adapter required')
    if tool == 'fixture':
        # Isolated protocol fixture, not a real provider compatibility claim.

        # Keep the fixture source readable and independent of shell quoting.
        script = 'import sys\nprint("NATIVE " + sys.argv[1], flush=True)\nfor line in sys.stdin:\n print("REPLY " + line.strip(), flush=True)\n'
        return [sys.executable, '-u', '-c', script, conversation]
    if conversation == 'latest':
        raise ValueError('exact native ID required, never latest')
    # Hermes/Gemini documented --resume forms; no provider compatibility claim
    # is made until the separately authorized native smoke runs.
    return [tool, 'resume' if tool == 'codex' else '--resume', conversation]
