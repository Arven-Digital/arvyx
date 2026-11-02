import {it,expect,vi} from 'vitest';
import {connectExternalAuthority} from './external-http';
import {onboardingRequest} from './public-onboarding';

it('lists and revokes a multi-resource grant without dropping scope',async()=>{
 const grant={id:'multi',issuer:'issuer',recipient:'cloud',resources:['task:A','workspace:review'],operations:['read'],created_at:'2026-01-01T00:00:00Z',expires_at:'2099-01-02T00:00:00Z',state:'active'};
 let revoked=false;
 const fetcher=vi.fn(async(url:any)=>new Response(JSON.stringify(url.endsWith('/config')?{issuer:'issuer',can_export:true,ttl_hours:24,recipients:[],resources:[]}:url.endsWith('/revoke')?(revoked=true,{}):url.endsWith('/grants')?[grant]:{...grant,state:revoked?'revoked':'active'})));
 const {adapter}=await connectExternalAuthority('http://127.0.0.1:1234','synthetic',fetcher);
 expect((await adapter.list())[0].resources).toEqual(grant.resources);
 expect((await adapter.revoke('multi')).resources).toEqual(grant.resources);
 expect(revoked).toBe(true);
});

it('never manufactures a confirmation at the transport boundary',async()=>{
 const fetcher=vi.fn();
 for(const path of ['/connect','/agents','/sessions/select'])await expect(onboardingRequest('synthetic',path,{},fetcher)).rejects.toThrow('confirmation');
 expect(fetcher).not.toHaveBeenCalled();
});

it('renders duplicate-name refusal as validation rather than an outage',async()=>{
 await expect(onboardingRequest('synthetic','/agents/name-check',{name:'STRASSE'},async()=>new Response(JSON.stringify({error:'duplicate_agent_name'}),{status:409}))).rejects.toThrow('already in use');
});

it('does not claim no effect after acknowledgement loss',async()=>{
 await expect(onboardingRequest('synthetic','/agents/commit',{consent_id:'reviewed',confirmed:true},async()=>{throw Error('lost response')})).rejects.toThrow('outcome is unknown');
});
