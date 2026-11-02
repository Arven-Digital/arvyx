"""MAIN issues; REMOTE confirms; MAIN separately approves the fingerprint.

Run in an installed environment satisfying the secret-edge extra
(cryptography>=50.0.1,<51). All state directories must be private mode 0700.

MAIN (keep the server running in a separate terminal)::

    python -m arvyx_control.machine_pairing_cli serve --state-dir "$MAIN_STATE" --port 8769
    python -m arvyx_control.machine_pairing_cli issue --state-dir "$MAIN_STATE" --actor owner

REMOTE, after installing the same supported package/extra::

    amc -confirm "$CODE" --state-dir "$REMOTE_STATE" --url http://127.0.0.1:8769 --name remote

For a different host, first establish an owner-approved authenticated tunnel on
REMOTE: ssh -N -L 8769:127.0.0.1:8769 user@MAIN. Never expose this HTTP service on
LAN/public interfaces. Tunnel provisioning is not performed automatically.

MAIN, compare the returned fingerprint with REMOTE through a trusted channel::

    python -m arvyx_control.machine_pairing_cli pending --state-dir "$MAIN_STATE"
    python -m arvyx_control.machine_pairing_cli approve "$FINGERPRINT" --state-dir "$MAIN_STATE" --actor owner --approve --review-snapshot "$CLAIM_JSON"

Copy the exact selected record from pending into CLAIM_JSON, including claim_id,
public_key, name, expiry and state. Both approve and deny require that reviewed
snapshot; a replacement claim is never selected implicitly.

Alternatively use deny FINGERPRINT --state-dir "$MAIN_STATE" --actor owner --review-snapshot "$CLAIM_JSON".
REMOTE check uses --state-dir "$REMOTE_STATE" --url URL --name remote.
Only issuance prints the short-lived code; claim responses/audit never do.
Claim consumes the invitation, not approval. Approval remains local to MAIN's
private store, requires --approve, and expires with the original invitation.
Enrollment does not confer root, task authority, filesystem access or grants.

Regression verification: test_machine_pairing_direction.py executes the installed
amc -confirm command against a separate server subprocess. Transport tests cover
Ed25519 forgery, challenge replay/expiry, persistence and revocation. No live
SSH host, provider, production service or external account is contacted by tests.
"""
import argparse
import json
import sys

from .machine_pairing_transport import PairingTransport, make_server, remote_action


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('serve', 'issue', 'check', 'confirm', 'approve', 'deny', 'pending'):
        child = commands.add_parser(command)
        child.add_argument('--state-dir', required=True)
        if command == 'serve':
            child.add_argument('--port', type=int, default=8769)
        elif command in ('confirm', 'check'):
            if command == 'confirm':
                child.add_argument('code')
            child.add_argument('--url', required=True)
            child.add_argument('--name', required=True)
        elif command in ('approve', 'deny'):
            child.add_argument('fingerprint')
            child.add_argument('--review-snapshot', required=True,
                               help='Exact JSON claim record copied from pending; never refresh implicitly')
            child.add_argument('--actor', required=True)
            if command == 'approve':
                child.add_argument('--approve', action='store_true')
        elif command == 'issue':
            child.add_argument('--actor', default='local-owner')
            child.add_argument('--ttl', type=float, default=300)
    args = parser.parse_args(argv)
    try:
        if args.command in ('confirm', 'check'):
            result = remote_action(args.state_dir, args.url, args.name, args.command, getattr(args, 'code', None))
        else:
            transport = PairingTransport(args.state_dir)
            try:
                if args.command == 'serve':
                    server = make_server(transport, args.port)
                    print(json.dumps({'url': f'http://127.0.0.1:{server.server_port}'}), flush=True)
                    try:
                        server.serve_forever()
                    finally:
                        server.server_close()
                    return 0
                if args.command == 'issue':
                    ticket = transport.store.issue(actor=args.actor, ttl=args.ttl)
                    result = {'code': ticket.code, 'expires_at': ticket.expires_at, 'status': 'issued_on_main'}
                elif args.command == 'pending':
                    with transport.store.lock:
                        rows = transport.store.db.execute("SELECT * FROM machine_pairing_codes WHERE state='claimed' AND expires>?", (transport.store._now(),)).fetchall()
                        result = {'claims': [transport.store._claim_record(row) for row in rows]}
                else:
                    snapshot = json.loads(args.review_snapshot)
                    fields = {'claim_id', 'fingerprint', 'name', 'public_key', 'expires', 'state'}
                    if (not isinstance(snapshot, dict) or set(snapshot) != fields
                            or not isinstance(snapshot['claim_id'], str) or not snapshot['claim_id']
                            or snapshot['fingerprint'] != args.fingerprint or snapshot['state'] != 'claimed'):
                        raise ValueError('exact reviewed claim required')
                    decision = transport.store.decide(args.fingerprint, actor=args.actor,
                                                      claim_id=snapshot['claim_id'], review_snapshot=snapshot,
                                                      approved=getattr(args, 'approve', False), deny=args.command == 'deny')
                    result = {'allowed': decision.allowed, 'reason': decision.reason}
            finally:
                transport.close()
        print(json.dumps(result))
        return 1 if result.get('allowed') is False else 0
    except (ValueError, OSError):
        print('Pairing failed: request denied; no enrollment performed.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
