"""Explicit private organizer/remote composition. No discovery or role enrollment."""
from pathlib import Path
from .remote_effect_fence import private_config,load_client
from .organizer_authority import OrganizerAuthority
from .organizer_delegation import DelegationService
from .executor_endpoint import ExecutorEndpoint
from .remote_delegation import RemoteDelegationEndpoint


def load_delegations(config):
    fields=private_config(config)
    if type(fields) is not dict or set(fields)!={'database','authority_database','organizer','remote_fence_config','endpoints'}:
        raise ValueError('closed trusted delegation runtime configuration required')
    if not Path(fields['authority_database']).is_file():
        raise PermissionError('existing independently provisioned organizer authority required; no automatic enrollment')
    policy=OrganizerAuthority(database=fields['authority_database']);endpoints={};fence=None
    try:
        actor=policy.identity_handle(fields['organizer'])
        if fields['remote_fence_config'] is not None:fence=load_client(fields['remote_fence_config'])
        for item in fields['endpoints']:
            if type(item) is not dict or set(item)!={'kind','machine','agent','session','configuration'}:
                raise ValueError('closed trusted endpoint configuration required')
            key=(item['machine'],item['agent'],item['session'])
            if key in endpoints:raise ValueError('duplicate exact endpoint refused')
            options=dict(item['configuration'])
            if item['kind']=='leaf':
                endpoint=ExecutorEndpoint(machine=item['machine'],agent=item['agent'],session=item['session'],**options)
            elif item['kind']=='remote':
                endpoint=RemoteDelegationEndpoint(machine=item['machine'],**options)
                binding=endpoint.receiver_binding
                if binding is not None and (binding['target']['agent_id'],binding['session'])!=(item['agent'],item['session']):
                    endpoint.close();raise PermissionError('remote exact agent/session differs from trusted receiver binding')
            else:raise ValueError('only closed authenticated leaf or remote endpoints supported')
            endpoints[key]=endpoint
        service=DelegationService(fields['database'],policy,actor,endpoints,remote_fence=fence)
        service._runtime_resources=(policy,fence,list(endpoints.values()))
        return service
    except BaseException:
        for endpoint in endpoints.values():
            if isinstance(endpoint,RemoteDelegationEndpoint):endpoint.close()
        if fence is not None:fence.close()
        policy.close();raise


def main(argv=None):
    import argparse,json
    from .local_onboarding import local_composition
    from .public_onboarding_api import make_server
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,required=True);args=parser.parse_args(argv)
    fields=private_config(args.config)
    if set(fields)!={'directory','vault','machine_id','capability','delegation_config','port'}:
        raise ValueError('closed private onboarding listener configuration required')
    port=fields.pop('port')
    api=local_composition(**fields)
    server=make_server(api,port=port)
    print(json.dumps(dict(origin='http://127.0.0.1:'+str(server.server_port),transport='loopback-or-explicit-approved-tunnel',provider_started=False)),flush=True)
    try:server.serve_forever()
    finally:server.server_close();api.close()


if __name__=='__main__':main()
