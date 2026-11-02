"""Authenticated durable final-effect permits between separately provisioned hosts.

Transport deadlines never cancel permits. No task can configure trust, an origin,
policy path, identity, key, receiver incarnation or reconciliation authority.
Production requires verified HTTPS; explicit numeric-loopback HTTP is fixtures only.
"""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import hmac
import http.client
import json
from .security import bounded_json_loads
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time
from urllib.parse import urlsplit
from .organizer_durable import private_database, _canonical, _ticket_record

PROTOCOL = 'amc-final-effect-v1'
OPERATIONS = frozenset(('preflight', 'acquire', 'check', 'settle', 'status'))


class RemoteEffectUnsettled(PermissionError):
    """Revocation has NOT completed. Retain and authenticate reconciliation."""
    code = 'remote_effect_unsettled'


def digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _hex(value, length=64):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{'+str(length)+'}', value) is not None


def _key(value):
    if not _hex(value):
        raise ValueError('separately provisioned 256-bit peer authentication key required')
    return bytes.fromhex(value)


def _mac(key, value):
    return hmac.new(_key(key), _canonical(value).encode(), hashlib.sha256).hexdigest()


def validate_binding(value):
    fields={'receiver_id','incarnation','epoch','target','session','workspace_identity','environments','policy_id'}
    if (type(value) is not dict or set(value)!=fields or not isinstance(value['receiver_id'],str)
            or not re.fullmatch('[A-Za-z0-9_-]{1,128}',value['receiver_id'])
            or not _hex(value['incarnation'],32) or type(value['epoch']) is not int or value['epoch']<0
            or type(value['target']) is not dict or set(value['target'])!={'machine_id','agent_id','workspace_id','connection_id'}
            or any(not isinstance(v,str) or not v or len(v)>4096 for v in value['target'].values())
            or not isinstance(value['session'],str) or not 1<=len(value['session'])<=256
            or type(value['workspace_identity']) is not list or len(value['workspace_identity'])!=2
            or any(type(v) is not int or v<0 for v in value['workspace_identity'])
            or type(value['environments']) is not list or not value['environments']
            or len(value['environments'])!=len(set(value['environments']))
            or set(value['environments'])-{'sandbox','host','root'} or not _hex(value['policy_id'])):
        raise ValueError('explicit complete receiver incarnation, target, workspace and independent policy binding required')
    return json.loads(_canonical(value))


def assert_no_unsettled(db):
    row=db.execute("SELECT permit_id FROM organizer_remote_permits WHERE status='unsettled' LIMIT 1").fetchone()
    if row is not None:
        raise RemoteEffectUnsettled('remote effect permit '+row[0]+' remains unsettled; revocation not completed; authenticated owner settlement required')


class RemoteFenceService:
    """Trusted coordinator. The independently keyed receiver holds a durable permit."""
    def __init__(self, authority, peers):
        if authority._backend is None:
            raise ValueError('existing durable coordinator authority required')
        self.authority=authority
        self.peers={}
        for identifier,fields in peers.items():
            if type(fields) is not dict or set(fields)!={'key','binding','organizer'}:
                raise ValueError('closed independently authenticated receiver provisioning required')
            _key(fields['key']);binding=validate_binding(fields['binding'])
            if identifier!=binding['receiver_id'] or not isinstance(fields['organizer'],str) or not fields['organizer']:
                raise ValueError('exact receiver and initiating organizer required')
            self.peers[identifier]=dict(fields,binding=binding)
        with authority._lock:
            self.authority_id=authority._backend.fence_identity()
            authority._backend.db.execute('CREATE TABLE IF NOT EXISTS organizer_remote_nonces(receiver TEXT NOT NULL,nonce TEXT NOT NULL,PRIMARY KEY(receiver,nonce))')

    def handle(self, envelope):
        """Pure authenticated handler, also the actual HTTP server's only dispatch."""
        if (type(envelope) is not dict or set(envelope)!={'message','mac'} or type(envelope['message']) is not dict
                or len(_canonical(envelope).encode())>16384):
            return 400,dict(error='invalid_fence_envelope')
        message=envelope['message']
        if not isinstance(message.get('receiver_id'),str):return 400,dict(error='invalid_fence_receiver')
        peer=self.peers.get(message['receiver_id'])
        if (peer is None or not isinstance(envelope['mac'],str)
                or not hmac.compare_digest(_mac(peer['key'],message),envelope['mac'])):
            return 401,dict(error='fence_peer_authentication_required')
        fields={'protocol','authority_id','receiver_id','nonce','operation','payload'}
        if (set(message)!=fields or message['protocol']!=PROTOCOL or message['authority_id']!=self.authority_id
                or not _hex(message['nonce'],32) or message['operation'] not in OPERATIONS or type(message['payload']) is not dict):
            return self._reply(peer,message,403,dict(error='fence_identity_or_operation_refused'))
        try:
            with self.authority._lock:
                db=self.authority._backend.db
                if self.authority._backend.fence_identity()!=self.authority_id:
                    raise PermissionError('coordinator incarnation changed; reprovision required')
                nonce_full=db.execute('SELECT COUNT(*) FROM organizer_remote_nonces').fetchone()[0]>=100000
                if nonce_full and message['operation'] not in ('status','settle'):
                    raise PermissionError('authenticated nonce capacity reached; explicit reconciliation required')
                if db.execute('SELECT 1 FROM organizer_remote_nonces WHERE receiver=? AND nonce=?',(message['receiver_id'],message['nonce'])).fetchone():
                    raise PermissionError('authenticated request replay refused')
                # At capacity, read-only status and exact unsettled-to-terminal
                # settlement remain available. Neither operation launches effects.
                if not nonce_full:
                    db.execute('INSERT INTO organizer_remote_nonces VALUES(?,?)',(message['receiver_id'],message['nonce']))
                # Keep anti-replay evidence even when the authenticated operation refuses.
                self.authority._backend.checkpoint()
                try:
                    result=self._operation(message['operation'],message['payload'],peer)
                    self.authority._backend.checkpoint()
                    status=200
                except (PermissionError,ValueError,KeyError,TypeError):
                    result=dict(error='fence_admission_refused',reconcile_required=True);status=403
            return self._reply(peer,message,status,result)
        except (PermissionError,ValueError):
            return self._reply(peer,message,403,dict(error='fence_authority_refused',reconcile_required=True))

    def _reply(self,peer,message,status,value):
        response=dict(protocol=PROTOCOL,authority_id=self.authority_id,receiver_id=message.get('receiver_id'),
            nonce=message.get('nonce'),operation=message.get('operation'),status=status,payload=value)
        return status,dict(message=response,mac=_mac(peer['key'],response))

    def _original(self,ticket,peer):
        plan,expires,token_hash=_ticket_record(self.authority,ticket)
        row=self.authority._backend.db.execute('SELECT receiver FROM organizer_effect_destinations WHERE token_hash=?',(token_hash,)).fetchone()
        if row is None or json.loads(row[0])!=peer['binding']:
            raise PermissionError('ticket was not explicitly bound to this receiving owner')
        binding=peer['binding'];target=binding['target']
        if ((plan['machine'],plan['executing_agent'],plan['session'])!=(target['machine_id'],target['agent_id'],binding['session'])
                or plan['environment'] not in binding['environments'] or plan['operation']!='invoke_'+plan['environment']
                or plan['goal']!='new-local-shell' or plan['decision']['initiating_organizer']!=peer['organizer']
                or plan['consent_expires_at']!=expires or type(plan['root_acknowledged']) is not bool
                or plan['environment']=='root' and plan['root_acknowledged'] is not True):
            raise PermissionError('exact original approval and receiver required')
        return plan,expires,token_hash

    def _operation(self,operation,payload,peer):
        db=self.authority._backend.db
        if operation in ('preflight','acquire'):
            if set(payload)!=({'ticket'} if operation=='preflight' else {'ticket','permit_id'}):
                raise ValueError('closed permit operation required')
            plan,expires,token_hash=self._original(payload['ticket'],peer)
            if operation=='preflight':
                return dict(plan=plan,expires=expires,binding=peer['binding'])
            permit=payload['permit_id']
            if not _hex(permit,32):raise ValueError('exact durable receiver permit required')
            record=dict(plan=plan,expires=expires,binding=peer['binding'],token_hash=token_hash)
            db.execute("INSERT INTO organizer_remote_permits VALUES(?,?,?,'unsettled')",(permit,peer['binding']['receiver_id'],_canonical(record)))
            db.execute("UPDATE organizer_effect_tickets SET status='remote-admitted' WHERE token_hash=?",(token_hash,))
            return dict(permit_id=permit,sha256=digest(record),plan=plan,expires=expires)
        required={'permit_id','sha256'} if operation in ('check','status') else {'permit_id','sha256','outcome','evidence_sha256','record'}
        if set(payload)!=required:raise ValueError('closed settlement required')
        row=db.execute('SELECT receiver,record,status FROM organizer_remote_permits WHERE permit_id=?',(payload['permit_id'],)).fetchone()
        if row is None and operation=='settle' and payload['outcome']=='no-effect-proven':
            # Lost acquire may never have reached this coordinator. Cancel the
            # exact original ticket atomically before attesting exclusion, so a
            # delayed first acquire cannot arrive after successful reconciliation.
            record=payload['record']
            if type(record) is not dict or set(record)!={'plan','expires','binding','token_hash'} or digest(record)!=payload['sha256']:
                raise PermissionError('exact retained original permit witness required')
            ticket=db.execute('SELECT record,expires,status FROM organizer_effect_tickets WHERE token_hash=?',(record['token_hash'],)).fetchone()
            destination=db.execute('SELECT receiver FROM organizer_effect_destinations WHERE token_hash=?',(record['token_hash'],)).fetchone()
            if (ticket is None or ticket[2]!='issued' or destination is None or json.loads(destination[0])!=peer['binding']
                    or record['binding']!=peer['binding'] or record['plan']!=json.loads(ticket[0]) or record['expires']!=ticket[1]
                    or not _hex(payload['evidence_sha256'])):
                raise PermissionError('lost permit cannot be excluded without exact authenticated original authority')
            db.execute("INSERT INTO organizer_remote_permits VALUES(?,?,?,'unsettled')",(payload['permit_id'],peer['binding']['receiver_id'],_canonical(record)))
            row=(peer['binding']['receiver_id'],_canonical(record),'unsettled')
        if row is None and operation=='status':
            return dict(permit_id=payload['permit_id'],status='not-observed-uncertain')
        if row is None or row[0]!=peer['binding']['receiver_id'] or digest(json.loads(row[1]))!=payload['sha256']:
            raise PermissionError('exact authenticated owner permit required')
        record=json.loads(row[1])
        if record['binding']!=peer['binding']:raise PermissionError('receiver incarnation changed')
        if operation=='check':
            if row[2]!='unsettled' or record['expires']<=time.time():raise PermissionError('original approval expired or permit settled')
        if operation=='settle':
            if (payload['record']!=record or row[2]!='unsettled' or payload['outcome'] not in ('effect-acknowledged','no-effect-proven')
                    or not _hex(payload['evidence_sha256'])):
                raise PermissionError('exact authenticated settlement evidence required; no replay')
            # Expiry is deliberately irrelevant to settlement. Uncertain permits
            # survive transport deadlines, leases, process death and store reopen.
            db.execute('UPDATE organizer_remote_permits SET status=? WHERE permit_id=?',(payload['outcome'],payload['permit_id']))
            db.execute("UPDATE organizer_effect_tickets SET status='settled' WHERE token_hash=?",(record['token_hash'],))
        return dict(permit_id=payload['permit_id'],status=payload.get('outcome',row[2]))


class RemoteFenceClient:
    """Only trusted owner configuration creates this client; task data cannot."""
    def __init__(self,database,*,origin,authority_id,receiver_id,key,binding,authority_database,organizer,local_organizer,
                 fixture_http=False,ca_file=None,timeout=2):
        from .organizer_durable import authority_fence_identity
        self.binding=validate_binding(binding);self.receiver_id=receiver_id;self.key=key;_key(key)
        if receiver_id!=binding['receiver_id'] or not _hex(authority_id):raise ValueError('trusted exact coordinator and receiver identities required')
        if type(fixture_http) is not bool or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=2:
            raise ValueError('explicit transport mode and bounded timeout required')
        self.origin,self.ca_file=_origin(origin,fixture_http,ca_file)
        ca_bytes=None;self._tls_context=None
        if not fixture_http:
            import ssl
            from .external_workspace import _read
            certificate=Path(self.ca_file)
            ca_bytes,_,_=_read(certificate.parent,(certificate.name,),1024*1024)
            # Pin the same CA bytes into the transport and durable trust record.
            # A later file replacement cannot silently change accepted issuers.
            cadata=ca_bytes.decode('ascii') if ca_bytes.startswith(b'-----BEGIN CERTIFICATE') else ca_bytes
            self._tls_context=ssl.create_default_context(cadata=cadata)
        self.authority_id=authority_id;self.timeout=timeout;self.fixture_http=fixture_http
        self.authority_database=Path(authority_database).resolve()
        if authority_fence_identity(self.authority_database)!=binding['policy_id']:
            raise PermissionError('independent receiver policy incarnation changed; reprovision explicitly')
        if any(not isinstance(v,str) or not v for v in (organizer,local_organizer)):
            raise ValueError('trusted original and independent local organizer mapping required')
        self.organizer,self.local_organizer=organizer,local_organizer
        self.db=private_database(database);self.lock=threading.RLock()
        self.db.execute('CREATE TABLE IF NOT EXISTS remote_owner_identity(singleton INTEGER PRIMARY KEY,record TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS remote_owner_permits(attempt TEXT PRIMARY KEY,permit_id TEXT UNIQUE NOT NULL,record TEXT NOT NULL,status TEXT NOT NULL)')
        from .cockpit_restart import boot_id
        info=Path(database).stat()
        identity=dict(authority=authority_id,receiver=receiver_id,binding=binding,origin=self.origin,
            transport='SYNTHETIC-loopback-HTTP' if fixture_http else 'verified-HTTPS',ca_sha256=None if ca_bytes is None else hashlib.sha256(ca_bytes).hexdigest(),
            key_sha256=hashlib.sha256(_key(key)).hexdigest(),policy=str(self.authority_database),organizer=organizer,local_organizer=local_organizer,
            database=[str(Path(database).resolve()),info.st_dev,info.st_ino,boot_id()])
        row=self.db.execute('SELECT record FROM remote_owner_identity WHERE singleton=1').fetchone()
        if row is not None and row[0]!=_canonical(identity):
            self.db.close();raise PermissionError('remote receiver store/trust changed; reconcile and reprovision, never adopt a copy')
        self.db.execute('INSERT OR IGNORE INTO remote_owner_identity VALUES(1,?)',(_canonical(identity),));self.db.commit()
        self.configuration_sha256=digest(identity)

    def close(self):self.db.close()

    def _exchange(self,envelope):
        from .http_bounds import bounded_connection, _validate_response_framing, _validate_response_complete
        from .locks import check_inherited_deadline
        parts=urlsplit(self.origin);raw=_canonical(envelope).encode()
        if self.fixture_http:connection=http.client.HTTPConnection(parts.hostname,parts.port)
        else:
            connection=http.client.HTTPSConnection(parts.hostname,parts.port or 443,context=self._tls_context)
        inherited=check_inherited_deadline()
        budget=self.timeout if inherited is None else min(self.timeout,inherited)
        with bounded_connection(connection,budget):
            connection.request('POST','/api/authority-fence',body=raw,headers={'Content-Type':'application/json','Content-Length':str(len(raw)),'Origin':self.origin})
            response=connection.getresponse()
            _validate_response_framing(response)
            body=response.read(16385)
            if len(body)>16384:raise ValueError('bounded authenticated fence response required')
            _validate_response_complete(response)
            return response.status,bounded_json_loads(body)

    def call(self,operation,payload):
        if operation not in OPERATIONS:raise ValueError('unsupported authenticated fence operation')
        message=dict(protocol=PROTOCOL,authority_id=self.authority_id,receiver_id=self.receiver_id,
            nonce=secrets.token_hex(16),operation=operation,payload=payload)
        status,envelope=self._exchange(dict(message=message,mac=_mac(self.key,message)))
        if type(envelope) is not dict or set(envelope)!={'message','mac'} or type(envelope['message']) is not dict:
            raise PermissionError('authenticated coordinator response required; outcome uncertain')
        response=envelope['message']
        if (not isinstance(envelope['mac'],str) or not hmac.compare_digest(_mac(self.key,response),envelope['mac'])
                or set(response)!={'protocol','authority_id','receiver_id','nonce','operation','status','payload'}
                or any(response.get(k)!=message[k] for k in ('protocol','authority_id','receiver_id','nonce','operation'))
                or response['status']!=status):
            raise PermissionError('coordinator identity or response authentication failed; outcome uncertain')
        if status!=200:raise PermissionError('authenticated remote effect admission refused; reconcile original attempt')
        return response['payload']

    def validate(self,ticket,plan=None):
        value=self.call('preflight',dict(ticket=ticket))
        if value.get('binding')!=self.binding or plan is not None and value.get('plan')!=json.loads(_canonical(plan)):
            raise PermissionError('authenticated original attempt or receiving owner mismatch')
        original=value['plan']
        if original['decision']['initiating_organizer']!=self.organizer or original['consent_expires_at']!=value['expires']:
            raise PermissionError('exact original actor and expiry required')
        return value

    def _local(self,policy,plan):
        if policy._backend.fence_identity()!=self.binding['policy_id']:
            raise PermissionError('independent receiver authority changed')
        actor=policy.identity_handle(self.local_organizer);worker=policy.identity_handle(plan['executing_agent'])
        if not policy.authorize(actor,operation=plan['operation'],machine=plan['machine'],executing_agent=worker).allowed:
            raise PermissionError('independent receiver execution policy refuses original approval')

    @contextmanager
    def guard(self,ticket,*,attempt,machine,agent,environment,root_acknowledged,owner):
        from .organizer_durable import _existing_authority
        from .reviewed_actions import assert_consent_active
        from .public_onboarding_api import assert_request_active
        expected=(self.binding['incarnation'],self.binding['epoch'],self.binding['target']['machine_id'])
        def owner_check():
            epoch=owner.db.execute('SELECT epoch FROM lifecycle_policy WHERE singleton=1').fetchone()[0]
            if (owner.incarnation,epoch,owner.host)!=expected or owner.delegation_remote_fence is not self:
                raise PermissionError('exact independently provisioned receiving owner incarnation required')
        policy=_existing_authority(self.authority_database)
        try:
            with self.lock,policy._lock:
                owner_check();value=self.validate(ticket);plan=value['plan'];expires=value['expires']
                if ((plan['request_id'],plan['machine'],plan['executing_agent'],plan['environment'],plan['root_acknowledged'])
                        !=(attempt,machine,agent,environment,root_acknowledged)):
                    raise PermissionError('final owner differs from authenticated original approval')
                self._local(policy,plan);assert_request_active();assert_consent_active(expires)
                permit=secrets.token_hex(16)
                record=dict(plan=plan,expires=expires,binding=self.binding,token_hash=hashlib.sha256(ticket['token'].encode()).hexdigest())
                sha=digest(record)
                # Before acquire can be sent: durable receiver ambiguity, never
                # replay a request after a lost permit response or process death.
                with self.db:self.db.execute("INSERT INTO remote_owner_permits VALUES(?,?,?,'uncertain')",(attempt,permit,_canonical(record)))
                policy._backend.db.execute("INSERT INTO organizer_remote_permits VALUES(?,?,?,'unsettled')",(permit,self.receiver_id,_canonical(record)))
                policy._backend.checkpoint()
                admitted=self.call('acquire',dict(ticket=ticket,permit_id=permit))
                if admitted!=dict(permit_id=permit,sha256=sha,plan=plan,expires=expires):
                    raise PermissionError('exact authenticated final permit required; outcome uncertain')
                def check():
                    assert_request_active();assert_consent_active(expires);owner_check();self._local(policy,plan)
                    self.call('check',dict(permit_id=permit,sha256=sha))
                    # Recheck after *all* blocking validation and network wait.
                    assert_request_active();assert_consent_active(expires);owner_check()
                check()
                yield check
                # Success means the actual owner fork/exec ACK/publication guard
                # returned. Errors intentionally do not settle/refund/release.
                evidence=digest(dict(permit_id=permit,sha256=sha,outcome='effect-acknowledged',owner=expected))
                self.call('settle',dict(permit_id=permit,sha256=sha,outcome='effect-acknowledged',evidence_sha256=evidence,record=record))
                policy._backend.db.execute("UPDATE organizer_remote_permits SET status='effect-acknowledged' WHERE permit_id=?",(permit,));policy._backend.checkpoint()
                with self.db:self.db.execute("UPDATE remote_owner_permits SET status='effect-acknowledged' WHERE attempt=?",(attempt,))
        finally:
            policy.close()  # No permit release in finally. Timeout is not cancellation.

    def reconcile(self,attempt,*,expected_sha256,outcome,evidence_sha256,confirmed=False):
        """Trusted authenticated recovery only, after caller proves no active admission.

        No automatic timer/lease path calls this. The private owner facade verifies
        stopped/settled local admission before accepting explicit operator evidence.
        """
        if confirmed is not True or outcome not in ('effect-acknowledged','no-effect-proven') or not _hex(evidence_sha256):
            raise PermissionError('explicit exact settlement evidence required')
        from .organizer_durable import _existing_authority
        policy=_existing_authority(self.authority_database)
        try:
            with self.lock,policy._lock:
                row=self.db.execute('SELECT permit_id,record,status FROM remote_owner_permits WHERE attempt=?',(attempt,)).fetchone()
                if row is None or row[2]!='uncertain' or digest(json.loads(row[1]))!=expected_sha256:
                    raise PermissionError('exact unsettled receiver witness required')
                payload=dict(permit_id=row[0],sha256=expected_sha256)
                status=self.call('status',payload)
                if status['status'] in ('unsettled','not-observed-uncertain'):
                    self.call('settle',dict(payload,outcome=outcome,evidence_sha256=evidence_sha256,record=json.loads(row[1])))
                elif status['status']!=outcome:
                    raise PermissionError('authenticated settlement differs; no replay or refund')
                policy._backend.db.execute('UPDATE organizer_remote_permits SET status=? WHERE permit_id=?',(outcome,row[0]));policy._backend.checkpoint()
                with self.db:self.db.execute('UPDATE remote_owner_permits SET status=? WHERE attempt=?',(outcome,attempt))
        finally:policy.close()


def _origin(origin,fixture_http,ca_file):
    parts=urlsplit(origin)
    if parts.username or parts.password or parts.path not in ('','/') or parts.query or parts.fragment or not parts.hostname:
        raise ValueError('explicit trusted coordinator origin required')
    if fixture_http:
        if parts.scheme!='http' or parts.hostname!='127.0.0.1' or not parts.port or ca_file is not None:
            raise ValueError('SYNTHETIC HTTP mode requires numeric IPv4 loopback and explicit port')
    elif parts.scheme!='https' or ca_file is None or not Path(ca_file).is_absolute() or not Path(ca_file).is_file():
        raise ValueError('production coordinator requires HTTPS and explicit trusted CA file; reachability is not trust')
    return origin.rstrip('/'),ca_file


def private_config(path):
    from .external_workspace import _read,_open_root,_open_file,_identity
    path=Path(path)
    raw,identity,root_identity=_read(path.parent,(path.name,),65536)
    with _open_root(path.parent) as root:
        info=os.fstat(root)
        if (info.st_dev,info.st_ino)!=root_identity:raise PermissionError('trusted config directory replaced')
        with _open_file(root,(path.name,)) as descriptor:
            info=os.fstat(descriptor)
            replaced=_identity(info)!=identity
        if replaced:raise PermissionError('trusted config inode changed during read')
    if not path.is_absolute() or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise PermissionError('private owned trusted fence configuration required')
    def unique(pairs):
        value=dict(pairs)
        if len(value)!=len(pairs):raise ValueError('duplicate trusted config fields')
        return value
    return bounded_json_loads(raw,object_pairs_hook=unique)


def load_client(path):
    fields=private_config(path)
    required={'database','origin','authority_id','receiver_id','key','binding','authority_database','organizer','local_organizer','fixture_http','ca_file'}
    if type(fields) is not dict or set(fields)!=required:raise ValueError('closed remote owner configuration required')
    return RemoteFenceClient(**fields)


def make_server(service,*,origin,fixture_http=False,certificate=None,private_key=None):
    """Explicit server factory; production TLS wraps this dedicated HMAC service."""
    from http.server import BaseHTTPRequestHandler
    from .public_onboarding_api import BoundedOnboardingServer
    parts=urlsplit(origin)
    if parts.username or parts.password or parts.path not in ('','/') or parts.query or parts.fragment or not parts.hostname:
        raise ValueError('explicit coordinator listener origin required')
    if fixture_http:
        if parts.scheme!='http' or parts.hostname!='127.0.0.1' or certificate or private_key:raise ValueError('fixture listener is numeric loopback HTTP only')
    elif parts.scheme!='https' or not certificate or not private_key:
        raise ValueError('production coordinator requires explicitly provisioned TLS certificate and private key')
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                if self.path!='/api/authority-fence' or self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))!=1:
                    raise ValueError
                size=int(self.headers['Content-Length'])
                if not 0<size<=16384 or self.headers.get('Content-Type')!='application/json':raise ValueError
                def unique(pairs):
                    value=dict(pairs)
                    if len(value)!=len(pairs):raise ValueError
                    return value
                raw=self.rfile.read(size)
                if len(raw)!=size:raise ValueError
                status,value=service.handle(bounded_json_loads(raw,object_pairs_hook=unique))
            except (ValueError,TypeError,KeyError):status,value=400,dict(error='invalid_fence_request')
            data=_canonical(value).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.end_headers()
            try:self.wfile.write(data)
            except OSError:pass  # Peer timeout cannot cancel a durably admitted permit.
        def log_message(self,*args):pass
    class FenceServer(BoundedOnboardingServer):
        def finish_request(self,request,address):
            # BoundedWorkers starts the non-renewable deadline in the worker
            # before this hook. Never handshake in the serial accept loop.
            if not fixture_http:request.do_handshake()
            return super().finish_request(request,address)
    server=FenceServer((parts.hostname,parts.port if parts.port is not None else (0 if fixture_http else 443)),Handler)
    if not fixture_http:
        import ssl
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate,private_key);server.socket=context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    return server


def main(argv=None):
    import argparse
    from .organizer_authority import OrganizerAuthority
    from .replica_authority import authority_context
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,required=True);args=parser.parse_args(argv)
    fields=private_config(args.config)
    if set(fields)!={'authority_database','vault','state','peers','origin','fixture_http','certificate','private_key'}:
        raise ValueError('closed coordinator configuration required')
    # No authority is provisioned by starting this service.
    if not Path(fields['authority_database']).is_file():raise PermissionError('existing independently provisioned coordinator database required')
    with authority_context(Path(fields['vault']),Path(fields['state'])):
        policy=OrganizerAuthority(database=fields['authority_database']);service=RemoteFenceService(policy,fields['peers'])
    # Worker callbacks must enter the same trusted authority context.
    original=service.handle
    def handle(envelope):
        with authority_context(Path(fields['vault']),Path(fields['state'])):return original(envelope)
    service.handle=handle
    server=make_server(service,**{k:fields[k] for k in ('origin','fixture_http','certificate','private_key')})
    print(_canonical(dict(authority_id=service.authority_id,transport='SYNTHETIC-loopback-HTTP' if fields['fixture_http'] else 'verified-HTTPS')),flush=True)
    try:server.serve_forever()
    finally:server.server_close();policy.close()


if __name__=='__main__':main()
