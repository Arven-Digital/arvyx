import {it,expect} from 'vitest';
import {onboardingRequest} from './public-onboarding';
it('maps clean metadata creation to the exact confirmed API schema',async()=>{
 let seen:any;
 const transport=(async(url:any,init:any)=>{seen={url,body:JSON.parse(init.body),headers:init.headers};return new Response(JSON.stringify({agent_id:'test',name:'Unique',status:'metadata_only'}),{status:201})}) as typeof fetch;
 const result=await onboardingRequest('local-test','/agents',{name:'Unique',harness:'fixture',environment:'metadata',identity_mode:'clean',confirmed:true},transport);
 expect(seen.url).toBe('/api/public-onboarding/agents/create');
 expect(seen.body).toEqual({name:'Unique',harness:'fixture',confirmed:true});
 expect(seen.headers.Authorization).toBe('Bearer local-test');
 expect(result.status).toBe('metadata_only');
});
