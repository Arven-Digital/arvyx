"""Authored result-readback regressions. NOT_EXECUTED under source-only scope."""
import contextlib
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from arvyx_control.authority_attempts import migrate_attempts
from arvyx_control.executor_endpoint import ExecutorEndpoint, result_query
from arvyx_control.local_executor_service import LocalExecutorService
from arvyx_control.organizer_delegation import DelegationService, canonical
from arvyx_control.remote_delegation import RemoteDelegationEndpoint


class ResultReadbackTests(unittest.TestCase):
    def plan(self):
        return dict(request_id='a'*32, receiving_leaf='b'*64,
                    delegation_fence=dict(authority_id='c'*64, token='d'*64),
                    machine='machine', executing_agent='agent', session='session',
                    operation='invoke_host', environment='host', goal='new-local-shell',
                    root_acknowledged=False, consent_expires_at=1, decision={})

    def leaf(self, directory, plan, status='completed'):
        service=object.__new__(LocalExecutorService)
        service.credential_sha256=hashlib.sha256(('x'*32).encode()).hexdigest()
        service.lock=threading.RLock()
        service.vault=Path(directory);service.state=Path(directory)
        service._verify_target=mock.Mock();service._verify_workspace=mock.Mock()
        service.database_path=Path(directory)/'leaf.db';service.database_path.touch()
        info=service.database_path.stat();service.database_identity=(info.st_dev,info.st_ino)
        service.binding={'owner':'original'}
        service.producer=mock.Mock();service.producer.inspect.return_value=service.binding
        service.receiving_leaf=plan['receiving_leaf']
        service.db=sqlite3.connect(':memory:');self.addCleanup(service.db.close)
        service.db.execute('CREATE TABLE executor_attempts(id TEXT PRIMARY KEY,payload TEXT NOT NULL,status TEXT NOT NULL,result TEXT)')
        witness=dict(plan,delegation_fence=dict(authority_id='c'*64,
                     token_sha256=hashlib.sha256(('d'*64).encode()).hexdigest()))
        service.db.execute('INSERT INTO executor_attempts VALUES(?,?,?,?)',
                           (plan['request_id'],canonical(witness),status,canonical({'owner_session':'exact'})))
        service.db.commit();migrate_attempts(service.db,'test-leaf')
        return service

    def read(self, service, query, credential='x'*32):
        with mock.patch('arvyx_control.replica_authority.authority_context',return_value=contextlib.nullcontext()), \
             mock.patch('arvyx_control.replica_authority.assert_mutation_authority'), \
             mock.patch('arvyx_control.public_onboarding_api.assert_request_active'):
            return service.dispatch('POST','/api/public-onboarding/executor/result','Bearer '+credential,query)

    def test_expired_effect_can_read_exact_completed_result_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan=self.plan();service=self.leaf(tmp,plan)
            for _ in range(2):
                status,result=self.read(service,result_query(plan))
                self.assertEqual(status,200)
                self.assertEqual(result,dict(request_id=plan['request_id'],status='completed',reference='owner-session:exact'))
            service.producer.create.assert_not_called()
            service.producer.plan.assert_not_called()

    def test_authentication_witness_incarnation_and_unknown_are_not_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan=self.plan();service=self.leaf(tmp,plan);query=result_query(plan)
            self.assertEqual(self.read(service,query,credential='z'*32)[0],401)
            self.assertEqual(self.read(service,dict(query,witness_sha256='e'*64))[0],403)
            self.assertEqual(self.read(service,dict(query,receiving_leaf='e'*64))[0],403)
            self.assertEqual(self.read(service,dict(query,request_id='e'*32))[0],404)
            self.assertEqual(self.read(service,dict(query,extra=True))[0],400)
            service.producer.create.assert_not_called()

    def test_ambiguous_leaf_record_never_promotes_or_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan=self.plan();service=self.leaf(tmp,plan,status='ambiguous')
            self.assertEqual(self.read(service,result_query(plan))[0],409)
            self.assertEqual(service.db.execute("SELECT status FROM authority_attempts WHERE namespace='executor_attempts'").fetchone()[0],'ambiguous')
            service.producer.create.assert_not_called()

    def test_endpoint_readback_only_uses_result_route_and_exact_response(self):
        endpoint=object.__new__(ExecutorEndpoint);endpoint.timeout=2
        query=result_query(self.plan())
        endpoint._call=mock.Mock(return_value=dict(request_id=query['request_id'],status='completed',reference='owner-session:exact'))
        self.assertEqual(endpoint.recover(query)['reference'],'owner-session:exact')
        self.assertEqual(endpoint._call.call_args.args,('executor/result',query))
        endpoint._call.return_value['request_id']='e'*32
        with self.assertRaises(OSError):endpoint.recover(query)

    def organizer(self, endpoint, plan):
        service=object.__new__(DelegationService)
        service.lock=threading.RLock()
        service.db=sqlite3.connect(':memory:');self.addCleanup(service.db.close)
        service.db.execute("CREATE TABLE organizer_requests(id TEXT PRIMARY KEY,digest TEXT NOT NULL,payload TEXT NOT NULL,expires REAL NOT NULL,status TEXT NOT NULL,decision TEXT,result TEXT,endpoint TEXT NOT NULL,consent TEXT NOT NULL)")
        service.db.execute('INSERT INTO organizer_requests VALUES(?,?,?,?,?,?,?,?,?)',
                           (plan['request_id'],'f'*64,canonical(plan),1,'ambiguous',None,None,'old','{}'))
        service.db.commit();migrate_attempts(service.db,'test-organizer')
        service.db.execute('CREATE TABLE organizer_result_queries(id TEXT PRIMARY KEY,query TEXT NOT NULL)')
        service._retain_query(plan);service.db.commit()
        service.endpoints={('machine','agent','session'):endpoint}
        return service

    def test_organizer_exact_readback_settles_once_without_execute(self):
        endpoint=object.__new__(ExecutorEndpoint)
        endpoint.recover=mock.Mock(return_value=dict(status='completed',reference='owner-session:exact'))
        endpoint.execute=mock.Mock()
        plan=self.plan();service=self.organizer(endpoint,plan)
        body=dict(consent_id=plan['request_id'],consent_sha256='f'*64)
        for _ in range(2):
            status,value=service.route('delegations/reconcile','POST',body)
            self.assertEqual((status,value['status']),(200,'completed'))
        endpoint.recover.assert_called_once_with(result_query(plan))
        endpoint.execute.assert_not_called()
        with self.assertRaises(PermissionError):
            service.route('delegations/reconcile','POST',dict(body,consent_sha256='e'*64))

    def test_failed_readback_stays_ambiguous_and_legacy_query_absence_refuses(self):
        endpoint=object.__new__(ExecutorEndpoint)
        endpoint.recover=mock.Mock(side_effect=OSError('lost response'));endpoint.execute=mock.Mock()
        plan=self.plan();service=self.organizer(endpoint,plan)
        body=dict(consent_id=plan['request_id'],consent_sha256='f'*64)
        self.assertEqual(service.route('delegations/reconcile','POST',body)[0],503)
        self.assertEqual(service.db.execute("SELECT status FROM authority_attempts WHERE namespace='organizer_requests'").fetchone()[0],'ambiguous')
        service.db.execute('DELETE FROM organizer_result_queries');service.db.commit()
        with self.assertRaises(PermissionError):service.route('delegations/reconcile','POST',body)
        endpoint.execute.assert_not_called()

    def test_remote_readback_requires_exact_recorded_link_and_no_execution(self):
        endpoint=object.__new__(RemoteDelegationEndpoint)
        endpoint.timeout=2;endpoint.lock=threading.RLock()
        endpoint.db=sqlite3.connect(':memory:');self.addCleanup(endpoint.db.close)
        endpoint.db.execute('CREATE TABLE remote_delegation_links(local_id TEXT PRIMARY KEY,remote_id TEXT,status TEXT NOT NULL)')
        query=result_query(self.plan())
        endpoint.db.execute('INSERT INTO remote_delegation_links VALUES(?,?,?)',(query['request_id'],query['request_id'],'ambiguous'))
        endpoint.db.commit();migrate_attempts(endpoint.db,'test-remote')
        endpoint.call=mock.Mock(return_value=dict(request_id=query['request_id'],status='completed',reference='owner-session:exact'))
        self.assertEqual(endpoint.recover(query),dict(status='remote_completed',reference=query['request_id']))
        self.assertEqual(endpoint.call.call_args.args,('delegations/result',query))
        with self.assertRaises(PermissionError):endpoint.recover(dict(query,request_id='e'*32))
        self.assertEqual(endpoint.call.call_count,1)

    def test_query_does_not_retain_raw_ticket_and_binds_entire_plan(self):
        plan=self.plan();query=result_query(plan)
        self.assertNotIn('d'*64,canonical(query))
        for key,value in (('goal','other'),('environment','root'),('consent_expires_at',2),('receiving_leaf','e'*64)):
            self.assertNotEqual(result_query(dict(plan,**{key:value})),query)
