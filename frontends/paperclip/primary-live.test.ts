import {it,expect} from 'vitest';
import {getPrimary} from './primary-agent';
import {SYNTHETIC_DEMO_CAPABILITY} from './connection';
// Explicit opt-in; only the existing loopback synthetic integration service.
it.skipIf(process.env.AMC_PRIMARY_LIVE!=='1')('reads real integrated primary authority without inventing or changing its selection',async()=>{
 const bootstrap=await fetch('http://127.0.0.1:18189/');
 const cookie=bootstrap.headers.getSetCookie().find(c=>c.startsWith('external_fixture=')&&!c.includes('Max-Age=0'))?.split(';')[0];
 expect(cookie).toBeTruthy();
 const transport:typeof fetch=(input,init)=>fetch(new URL(String(input),'http://127.0.0.1:18189'),{...init,headers:{Cookie:cookie!}});
 const snapshot=await transport('/api/snapshot');
 expect(snapshot.status).toBe(200);
 const primary=await getPrimary(SYNTHETIC_DEMO_CAPABILITY,transport);
 expect(primary.agents.length).toBeGreaterThan(0);
 expect(primary.primary_agent_id).not.toBeNull();
 const repeat=await getPrimary(SYNTHETIC_DEMO_CAPABILITY,transport);
 expect(repeat.primary_agent_id).toBe(primary.primary_agent_id);
 expect(repeat.revision).toBe(primary.revision);
});
