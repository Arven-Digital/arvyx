import {z} from 'zod';
import {exclusions,type DelegationRecord,type ExternalDelegationAdapter,type ResourceKind} from './external-delegation';
export const manifestSchema=z.object({coverage:z.enum(['selection','workspace']),complete:z.boolean(),files:z.array(z.object({path:z.string(),size_bytes:z.number().int().nonnegative(),sha256:z.string().regex(/^[a-f0-9]{64}$/)})),excluded:z.array(z.object({path:z.string(),reason:z.string()}))});
const resource=z.object({kind:z.enum(['prompt','task','skill','artifact','workspace']),id:z.string().min(1),manifest:manifestSchema.optional()});
const configSchema=z.object({principal:z.string().min(1),role:z.literal('issuer'),can_export:z.boolean(),recipients:z.array(z.object({id:z.string().min(1),label:z.string(),location:z.enum(['cloud','local'])})),resources:z.array(resource),operations:z.array(z.string()).default([]),expiry_hours:z.literal(24)});
const date=z.union([z.string(),z.number()]).transform(v=>typeof v==='number'?new Date(v*1000).toISOString():v).refine(v=>Number.isFinite(Date.parse(v)));
const grantSchema=z.object({id:z.string().min(1),issuer:z.string(),recipient:z.string(),resources:z.array(z.string()).min(1),operations:z.array(z.string()),created_at:date,expires_at:date,state:z.enum(['active','revoked','expired','unavailable'])});
const auditDetails=z.object({grant_id:z.string().max(512),principal:z.string().max(512).optional(),resource:z.string().max(512).optional(),operation:z.string().max(512).optional(),allowed:z.boolean().optional(),issuer:z.string().max(512).optional(),recipient:z.string().max(512).optional(),actor:z.string().max(512).optional(),task_id:z.string().max(512).optional(),attempt_id:z.string().max(512).optional()}).strict();
const auditPageSchema=z.object({grant_id:z.string().min(1),coverage:z.literal('scope-indexed-events-only'),items:z.array(z.object({sequence:z.number().int().positive().max(Number.MAX_SAFE_INTEGER),timestamp:date,event:z.string().max(128),details:auditDetails}).strict()).max(100),has_more:z.boolean(),next_cursor:z.string().min(1).max(2048).nullable()}).strict();
export async function connectFixtureAuthority(fetcher:typeof fetch=fetch){
 if(typeof location==='undefined')throw new Error('Browser origin required');
 return connectExternalAuthority(location.origin,'',fetcher,true);
}
export async function connectExternalAuthority(base:string,bearer:string,fetcher:typeof fetch=fetch,fixture=false){
 const url=new URL(base);const loopback=['127.0.0.1','localhost','[::1]'].includes(url.hostname);
 const sameOrigin=typeof location!=='undefined'&&url.origin===location.origin;
 if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||!(url.protocol==='http:'&&loopback||url.protocol==='https:'&&sameOrigin)||(fixture?(!sameOrigin||!loopback||url.protocol!=='http:'):!bearer.trim()))throw new Error('Use an explicit loopback HTTP or same-origin HTTPS service and issuer credential.');
 async function request(path:string,body?:unknown){const response=await fetcher(url.origin+path,{method:body===undefined?'GET':'POST',headers:{...(fixture?{}:{Authorization:`Bearer ${bearer}`}),...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',credentials:fixture?'same-origin':'omit',cache:'no-store',referrerPolicy:'no-referrer'});if(!response.ok)throw new Error(`External authority refused request (${response.status}).`);return response.json()}
 const raw=await request('/external/config');
 if(fixture&&raw.fixture_only!==true)throw new Error('Explicit fixture composition required');
 const config=configSchema.parse(raw.issuer?{...raw,principal:raw.issuer,role:'issuer',expiry_hours:raw.ttl_hours}:raw);
 function record(value:unknown):DelegationRecord{const g=grantSchema.parse(value);if(g.issuer!==config.principal)throw new Error('Issuer mismatch');const [kind,...parts]=g.resources[0].split(':');if(!['prompt','task','skill','artifact','workspace'].includes(kind)||g.resources.some(key=>! /^(prompt|task|skill|artifact|workspace):.+$/.test(key)))throw new Error('Unsupported grant scope');return {grantedOperations:[...g.operations],resources:[...g.resources],id:g.id,issuer:g.issuer,recipientId:g.recipient,kind:kind as ResourceKind,resource:parts.join(':'),operations:[...(g.operations.includes('read')?['read' as const]:[]),...(g.operations.includes('submit')?['submit-result' as const]:[])],createdAt:g.created_at,expiresAt:g.expires_at,state:g.state,exclusions:[...exclusions]}}
 const detail=async(id:string,operations?:string[])=>{const value=grantSchema.parse(await request('/external/grants/'+encodeURIComponent(id)));if(operations&&JSON.stringify([...new Set(value.operations)].sort())!==JSON.stringify([...operations].sort()))throw new Error('Issued grant operations mismatch');return record(value)};
 const adapter:ExternalDelegationAdapter={inspect:async id=>{const confirmed=await detail(id);if(confirmed.id!==id)throw new Error('Grant identity mismatch');return confirmed},available:config.can_export,unavailableReason:'Authenticated issuer has no export authority.',audit:async(id,cursor)=>{
  const query=new URLSearchParams({limit:'50'});if(cursor!==undefined)query.set('cursor',cursor);
  const page=auditPageSchema.parse(await request('/external/grants/'+encodeURIComponent(id)+'/audit?'+query));
  if(page.grant_id!==id||page.items.some(item=>item.details.grant_id!==id)||page.has_more!==(page.next_cursor!==null)||page.has_more&&!page.items.length||page.items.some((item,index)=>index>0&&item.sequence<=page.items[index-1].sequence))throw new Error('Audit page scope or ordering mismatch');
  return page;
 },list:async()=>z.array(grantSchema).parse(await request('/external/grants')).map(record),issue:async draft=>{
 if(!config.can_export||!config.recipients.some(r=>r.id===draft.recipientId)||!config.resources.some(r=>r.kind===draft.kind&&r.id===draft.resource)||!Number.isFinite(Date.parse(draft.expiresAt))||Date.parse(draft.expiresAt)<=Date.now()||Date.parse(draft.expiresAt)>Date.now()+86400000)throw new Error('Choose a registered selected resource and a future expiry within 24 hours.');
 if(!draft.operations.length||draft.operations.some(op=>!['read','submit-result'].includes(op)))throw new Error('Unsupported operations');
 const operations=[...new Set(draft.operations.map(op=>op==='read'?'read':'submit'))];
 if(operations.some(op=>!config.operations.includes(op))||(operations.includes('submit')&&draft.kind!=='task'))throw new Error('Selected operation is unavailable for this issuer or resource.');
 const selected=config.resources.find(r=>r.kind===draft.kind&&r.id===draft.resource);
 if(draft.kind!=='task'&&!selected?.manifest)throw new Error('Exact selected resource manifest unavailable; no grant issued.');
 const reviewed_manifests=draft.kind!=='task'?{[`${draft.kind}:${draft.resource}`]:selected!.manifest}:{};
 const issued=z.object({id:z.string().min(1)}).parse(await request('/external/grants',{recipient:draft.recipientId,resources:[`${draft.kind}:${draft.resource}`],operations,reviewed_manifests,expires_at:draft.expiresAt,provenance:'paperclip-explicit-issuer-ui'}));const confirmed=await detail(issued.id,operations);if(Date.parse(confirmed.expiresAt)!==Date.parse(draft.expiresAt)||confirmed.id!==issued.id||confirmed.resources?.length!==1||confirmed.resources[0]!==`${draft.kind}:${draft.resource}`||confirmed.state!=='active'||confirmed.recipientId!==draft.recipientId||confirmed.resource!==draft.resource||confirmed.kind!==draft.kind||JSON.stringify([...confirmed.operations].sort())!==JSON.stringify([...new Set(draft.operations)].sort()))throw new Error('Issued grant readback mismatch');return confirmed;
 },revoke:async id=>{await request('/external/grants/'+encodeURIComponent(id)+'/revoke',{});const confirmed=await detail(id);if(confirmed.id!==id||confirmed.state!=='revoked')throw new Error('Revocation not confirmed');return confirmed}};
 return {config,adapter};
}
export type ExternalConnection=Awaited<ReturnType<typeof connectExternalAuthority>>;
