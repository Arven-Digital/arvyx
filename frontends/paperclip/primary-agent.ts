export type PrimaryState={primary_agent_id:string|null;primary_connected:boolean;revision:number;can_set_primary:boolean;agents:{id:string;display_name?:string;connected:boolean}[]};
export function parsePrimary(value:unknown):PrimaryState{
 const v=value as PrimaryState;
 if(!v||!(v.primary_agent_id===null||typeof v.primary_agent_id==='string'&&v.primary_agent_id.length>0)||typeof v.primary_connected!=='boolean'||!Number.isSafeInteger(v.revision)||v.revision<0||typeof v.can_set_primary!=='boolean'||!Array.isArray(v.agents)||v.agents.some(a=>!a||typeof a.id!=='string'||!a.id||typeof a.connected!=='boolean'||a.display_name!==undefined&&typeof a.display_name!=='string')||new Set(v.agents.map(a=>a.id)).size!==v.agents.length||v.primary_agent_id===null&&v.primary_connected)throw Error('Invalid primary-agent authority response.');
 const selected=v.agents.find(a=>a.id===v.primary_agent_id);
 if(v.primary_agent_id!==null&&(!selected||selected.connected!==v.primary_connected))throw Error('Invalid primary-agent authority response.');
 return v;
}
import {workspaceRequest as options} from './workspace-request';
export async function getPrimary(capability:string,transport:typeof fetch=fetch):Promise<PrimaryState>{
 const response=await transport('/api/primary-agent',options(capability));
 if(!response.ok)throw Error('Primary-agent authority unavailable or unauthorized. No selection inferred.');
 return parsePrimary(await response.json());
}
export async function setPrimary(capability:string,agentId:string,revision:number,transport:typeof fetch=fetch):Promise<PrimaryState>{
 const base=options(capability);
 if(typeof agentId!=='string'||!agentId||!Number.isSafeInteger(revision)||revision<0)throw Error('Invalid primary-agent selection.');
 const response=await transport('/api/primary-agent',{...base,method:'POST',headers:{...base.headers,'Content-Type':'application/json'},body:JSON.stringify({agent_id:agentId,revision})});
 if(!response.ok)throw Error('Change refused or delivery uncertain. Refresh before another action. No automatic retry.');
 const actual=await getPrimary(capability,transport);
 if(actual.primary_agent_id!==agentId||actual.revision<=revision)throw Error('Change not confirmed by authority. Refresh before another action.');
 return actual;
}
