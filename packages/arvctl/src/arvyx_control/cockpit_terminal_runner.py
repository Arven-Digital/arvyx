"""Durable single-step delegated native PTY driver. No provider calls here.

The injected driver is an existing authorized operator adapter, not terminal
output or a command parser. Socket clients cannot reserve/settle/deliver prompts.
Reservation is committed before the driver runs; cancellation is checked again
before staging text and again before the separate Enter key. A crash/partial
write waits for human reconciliation and is never replayed.
"""
import os
import json
from pathlib import Path
import subprocess
import selectors
import time


class JsonOperator:
    """Explicit local executable protocol, no shell or ambient provider secrets.

    The operator owner must supply an approved existing driver. This class does
    not select a provider, create an agent identity or load credential files.
    """
    def __init__(self, argv, *, cwd):
        if (not isinstance(argv, list) or not argv or len(argv) > 16
                or any(not isinstance(arg, str) or not arg or len(arg) > 4096 or '\x00' in arg for arg in argv)):
            raise ValueError('explicit bounded operator argv required')
        executable = Path(argv[0]).resolve(strict=True)
        if not executable.is_file() or executable.stat().st_mode & 0o022 or not os.access(executable, os.X_OK):
            raise ValueError('trusted explicit operator executable required')
        self.argv = [str(executable), *argv[1:]]
        self.cwd = Path(cwd).resolve(strict=True)
        if not self.cwd.is_dir():
            raise ValueError('operator cwd must exist')

    def __call__(self, context):
        from .brokers import _wait_owned_command, _cleanup_owned_command, _require_owned_command_support
        _require_owned_command_support()
        payload = json.dumps(context).encode('utf-8')
        if len(payload) > 1024 * 1024:
            raise ValueError('operator context exceeds protocol cap')
        deadline = time.monotonic() + 30
        process = subprocess.Popen(self.argv, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
            start_new_session=True, cwd=self.cwd,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.cwd)})
        output = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
                selector.register(process.stdout, selectors.EVENT_READ)
                sent = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('operator response timed out; nothing retried')
                    for key, _ in selector.select(remaining):
                        if key.fileobj is process.stdin:
                            try:
                                sent += os.write(key.fd, payload[sent:sent + 4096])
                            except BrokenPipeError:
                                sent = len(payload)
                            if sent == len(payload):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            # Read at most the remaining cap plus ONE sentinel,
                            # before decoding, JSON parsing or output accumulation.
                            chunk = os.read(key.fd, min(4096, 65537 - len(output)))
                            if not chunk:
                                selector.unregister(process.stdout)
                            elif len(output) + len(chunk) > 65536:
                                raise ValueError('operator response exceeds protocol cap')
                            else:
                                output.extend(chunk)
            if _wait_owned_command(process, deadline) != 0:
                raise ValueError('operator driver failed; nothing retried')
        except (OSError, TimeoutError):
            raise ValueError('operator transport failed; nothing retried') from None
        finally:
            _cleanup_owned_command(process)
        return json.loads(output.decode('utf-8'))


def run_configured(owner, stop):
    """Only explicit active delegations; no restart reactivation or write replay."""
    while not stop.wait(.25):
        with owner.lock:
            rows = [dict(row) for row in owner.db.execute("SELECT * FROM delegations WHERE status='active'")]
        for row in rows:
            if stop.is_set():
                return
            driver = owner.operator_drivers.get(row['operator'])
            if driver is None:
                continue
            try:
                outcome = step(owner, row['session'], actor=row['operator'], driver=driver)
                if outcome['outcome'] not in {'delivered', 'waiting', 'review'}:
                    raise ValueError('delivery requires reconciliation')
            except Exception:
                with owner.lock:
                    owner.db.execute("UPDATE delegations SET status=CASE WHEN pending IS NULL THEN 'paused' ELSE 'ambiguous' END WHERE session=? AND generation=? AND status='active'",
                                     (row['session'], row['generation']))
                    owner.db.execute('INSERT OR REPLACE INTO session_attention VALUES(?,?,?)',
                                     (row['session'], 'human', 'Configured operator paused; inspect native state. No automatic retry.'))
                    owner.db.commit()


def step(owner, sid, *, actor, driver):
    with owner.lock:
        row = owner.delegation(sid, actor=actor)
        if row is None:
            raise ValueError('explicit delegation required')
        if owner.db.execute('SELECT 1 FROM staged_input WHERE session=?', (sid,)).fetchone():
            raise ValueError('staged input requires human reconciliation; no retry')
        generation = row['generation']
        owner._delegated(sid, generation, actor)
        if owner.native(sid, actor='operator') is None:
            raise ValueError('native conversation binding required')
        observed_live = owner.live.get(sid)
        if not observed_live or observed_live['attached']:
            raise ValueError('native process unavailable or human attached')
        observed_fd = observed_live['fd']
        observed_epoch = observed_live.get('attachment_epoch', 0)
        observed_human_revision = observed_live.get('human_input_revision', 0)
        frame = owner.read(sid, actor='operator', cursor=row['cursor'])
        if frame['truncated']:
            raise ValueError('history gap; human reconciliation required')
        if frame['cursor'] == row['cursor']:
            owner.db.execute('INSERT OR REPLACE INTO session_attention VALUES (?, ?, ?)',
                             (sid, 'human', 'No new native output; operator waiting without a prompt retry.'))
            owner.db.commit()
            return {'outcome': 'waiting', 'cursor': frame['cursor']}
        reservation = owner.reserve_prompt(sid, generation=generation, cursor=row['cursor'], actor=actor)
        delivery = reservation['pending']
    try:
        decision = driver({'goal': row['goal'], 'limits': row['limits'],
                           'conversation': owner.native(sid, actor='operator'),
                           'delta': frame['output'], 'cursor': frame['cursor']})
        if not isinstance(decision, dict) or decision.get('action') not in {'prompt', 'wait', 'review'}:
            raise ValueError('invalid operator decision')
        action = decision['action']
        text = decision.get({'prompt': 'text', 'wait': 'reason', 'review': 'evidence'}[action])
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 4095 or '\x00' in text:
            raise ValueError('bounded prompt/reason/evidence required')
        if action == 'prompt' and any(ord(char) < 32 or ord(char) == 127 for char in text):
            raise ValueError('prompt control keys are forbidden; submit is separately fenced')
        from .control import _reject_secret_shaped_text
        _reject_secret_shaped_text(operator_decision=text)
    except Exception:
        with owner.lock:
            current = owner.delegation(sid, actor='operator')
            if current and current['generation'] == generation and current['pending'] == delivery:
                owner.settle_prompt(sid, generation=generation, delivery=delivery, outcome='not-delivered', actor=actor)
        raise
    with owner.lock:
        current = owner._delegated(sid, generation, actor)
        if current['pending'] != delivery:
            raise ValueError('stale delivery reservation')
        if action != 'prompt':
            owner.settle_prompt(sid, generation=generation, delivery=delivery, outcome='not-delivered', actor=actor)
            owner.db.execute('UPDATE delegations SET cursor=?, status=? WHERE session=?',
                             (frame['cursor'], 'review' if action == 'review' else 'active', sid))
            owner.db.execute('INSERT OR REPLACE INTO session_attention VALUES (?, ?, ?)',
                             (sid, 'review' if action == 'review' else 'human', text))
            owner.db.commit()
            return {'outcome': 'review' if action == 'review' else 'waiting', 'cursor': frame['cursor']}
        live = owner.live.get(sid)
        if not live or live['fd'] is None or owner._get(sid)['status'] != 'running':
            owner.settle_prompt(sid, generation=generation, delivery=delivery, outcome='not-delivered', actor=actor)
            raise ValueError('native process unavailable; no prompt queued')
        # Human attachment always wins; no automatic takeover or child interrupt.
        if (live is not observed_live or live['fd'] != observed_fd
                or live.get('attachment_epoch', 0) != observed_epoch
                or live.get('human_input_revision', 0) != observed_human_revision
                or live['attached']):
            owner.settle_prompt(sid, generation=generation, delivery=delivery, outcome='not-delivered', actor=actor)
            raise ValueError('human attached; delegated prompt withheld')
        # Interactive editors can treat an Enter in the same input burst as a
        # pasted newline. Stage text, then submit separately after their debounce.
        # The durable reservation covers BOTH writes; never replay partial input.
        payload = text.encode()
        with live['input_lock']:
            if live['input'] or live['input_error']:
                owner.settle_prompt(sid, generation=generation, delivery=delivery, outcome='not-delivered', actor=actor)
                raise ValueError('PTY input unavailable; no automatic retry')
            # Commit an independent fence BEFORE touching the editor. It survives
            # revocation, generation replacement, owner crash and write errors.
            owner.db.execute('INSERT OR REPLACE INTO staged_input VALUES(?,?)', (sid, delivery))
            owner.db.commit()
            try:
                written = os.write(live['fd'], payload)
            except BlockingIOError:
                written = 0
            except OSError:
                written = -1
            outcome = 'delivered' if written == len(payload) else ('not-delivered' if written == 0 else 'ambiguous')
            if written > 0:
                live['written_bytes'] += written
        if outcome != 'delivered':
            owner.db.execute('UPDATE delegations SET status=?, pending=? WHERE session=?',
                             ('ambiguous' if outcome == 'ambiguous' else 'active',
                              delivery if outcome == 'ambiguous' else None, sid))
            owner.db.commit()
            return {'outcome': outcome, 'delivery': delivery, 'cursor': frame['cursor']}
        attachment_epoch = live.get('attachment_epoch', 0)
        staged_bytes = live['written_bytes']
    # Do not hold the owner lock during the editor debounce: human takeover must
    # revoke immediately. A revoked reservation can never submit the staged text.
    time.sleep(.15)
    with owner.lock:
        current = owner._delegated(sid, generation, actor)
        if current['pending'] != delivery:
            raise ValueError('stale delivery reservation')
        current_live = owner.live.get(sid)
        if (current_live is not live or live['fd'] is None or live['attached']
                or live.get('attachment_epoch', 0) != attachment_epoch
                or live['written_bytes'] != staged_bytes or owner._get(sid)['status'] != 'running'):
            outcome = 'ambiguous'
        else:
            with live['input_lock']:
                try:
                    written = os.write(live['fd'], b'\r') if not live['input'] and not live['input_error'] else 0
                except (BlockingIOError, OSError):
                    written = 0
                if written > 0:
                    live['written_bytes'] += written
                outcome = 'delivered' if written == 1 else 'ambiguous'
        # Settle and advance the read cursor in ONE durable transaction. A crash
        # before commit leaves the intent pending/ambiguous, never resendable.
        owner.db.execute('UPDATE delegations SET status=?, pending=?, cursor=? WHERE session=?',
                         ('ambiguous' if outcome == 'ambiguous' else 'active',
                          delivery if outcome == 'ambiguous' else None,
                          frame['cursor'] if outcome == 'delivered' else row['cursor'], sid))
        if outcome == 'delivered':
            owner.db.execute('DELETE FROM staged_input WHERE session=? AND delivery=?', (sid, delivery))
            owner.db.execute('DELETE FROM session_attention WHERE session=?', (sid,))
        owner.db.commit()
        return {'outcome': outcome, 'delivery': delivery, 'cursor': frame['cursor']}
