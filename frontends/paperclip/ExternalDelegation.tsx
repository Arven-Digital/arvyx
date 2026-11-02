import React,{useEffect,useId,useRef,useState} from 'react';
import {Button} from './vendor/components/ui/button';
import {Card,CardContent,CardHeader,CardTitle} from './vendor/components/ui/card';
import {Badge} from './vendor/components/ui/badge';
import {delegationState,disclosureWarning,exclusions,prepareDelegation,unavailableDelegationAdapter,type DelegationDraft,type DelegationRecord,type ExternalDelegationAdapter,type Recipient,type ResourceKind} from './external-delegation';
import './ExternalDelegation.css';
import {DelegationAudit} from './DelegationAudit';
const noOperations:readonly string[]=[];
export interface ExternalDelegationProps {recipients:readonly Recipient[];canExport?:boolean;operations?:readonly string[];adapter?:ExternalDelegationAdapter;resources?:readonly {kind:Exclude<ResourceKind,'artifacts'>;id:string;manifest?:{coverage:string;complete:boolean;files:{path:string;size_bytes:number;sha256:string}[];excluded:{path:string;reason:string}[]}}[]}
/** Deliberately unmounted until a real authority adapter and authenticated issuer are supplied. */
export function ExternalDelegation({recipients,canExport=false,adapter=unavailableDelegationAdapter,resources,operations=noOperations}:ExternalDelegationProps){
 const uid=useId();const busy=useRef(false);
 const [savedDraft,setDraft]=useState<DelegationDraft>({recipientId:'',kind:resources?.[0]?.kind??'task',resource:'',operations:[],expiryHours:24,acknowledged:false});
 const [uncertainRevokes,setUncertainRevokes]=useState<string[]>([]);
 const [records,setRecords]=useState<DelegationRecord[]>([]);const [pending,setPending]=useState(false);const [uncertain,setUncertain]=useState(false);const [message,setMessage]=useState('');const [revokeId,setRevokeId]=useState('');const [now,setNow]=useState(Date.now());
 useEffect(()=>{const id=setInterval(()=>setNow(Date.now()),30000);return()=>clearInterval(id)},[]);
 const kinds:readonly ResourceKind[]=resources?[...new Set(resources.map(r=>r.kind))]:['task','prompt','skill','artifacts','workspace'];
 function reconcile(d:DelegationDraft):DelegationDraft{
  const kind=kinds.includes(d.kind)?d.kind:(kinds[0]??'task');
  const changed=kind!==d.kind||!!(resources&&d.resource&&!resources.some(r=>r.kind===kind&&r.id===d.resource));
  const permitted=d.operations.filter(op=>operations.includes(op==='read'?'read':'submit')&&(op!=='submit-result'||kind==='task'));
  return {...d,kind,resource:changed?'':d.resource,operations:permitted,acknowledged:changed||permitted.length!==d.operations.length?false:d.acknowledged};
 }
 const draft=reconcile(savedDraft);
 useEffect(()=>setDraft(d=>({...reconcile(d),acknowledged:false})),[resources,operations]);
 const update=(patch:Partial<DelegationDraft>)=>setDraft(d=>({...reconcile(d),acknowledged:false,...patch}));
 const manifest=resources?.find(r=>r.kind===draft.kind&&r.id===draft.resource)?.manifest;
 let error='';try{if(!kinds.length)throw Error('No registered work is available.');prepareDelegation(draft,recipients,now);if(resources&&draft.kind==='workspace'&&!manifest)throw Error('Exact resource manifest unavailable. Refresh the service connection before sharing.')}catch(e){error=(e as Error).message}
 const managementEnabled=adapter.available&&canExport&&!pending;
 const enabled=managementEnabled&&!uncertain;
 async function refresh(){if(busy.current||!adapter.available)return;busy.current=true;setPending(true);try{setRecords(await adapter.list());setMessage('Authority records refreshed. Unknown issuance remains unresolved; refresh is not proof of a mutation outcome.');}catch{setMessage('Authority unavailable. Displayed records may be stale.');}finally{busy.current=false;setPending(false)}}
 async function mutate(action:()=>Promise<DelegationRecord>,grantId?:string){if(!(grantId?managementEnabled&&!uncertainRevokes.includes(grantId):enabled)||busy.current)return;busy.current=true;setPending(true);setMessage('');try{const record=await action();setRecords(rs=>[record,...rs.filter(r=>r.id!==record.id)]);setMessage('Authority-confirmed record received.');setRevokeId('');}catch{if(grantId)setUncertainRevokes(ids=>[...new Set([...ids,grantId])]);else setUncertain(true);setMessage('Outcome unresolved. No automatic retry. Unrelated revocations remain available. Unknown issuance requires exact authority evidence; refreshing does not clear it.');}finally{busy.current=false;setPending(false)}}
 async function reconcileRevoke(id:string){
  if(busy.current||!adapter.inspect)return;busy.current=true;setPending(true);
  try{const record=await adapter.inspect(id);if(record.id!==id||record.state!=='revoked')throw Error('No exact revoked receipt');setRecords(rs=>[record,...rs.filter(r=>r.id!==id)]);setUncertainRevokes(ids=>ids.filter(value=>value!==id));setMessage('Exact grant revocation confirmed by authority.');}
  catch{setMessage('Revocation remains unresolved. No mutation replayed.');}finally{busy.current=false;setPending(false)}
 }
 return <section className="external-delegation" aria-labelledby={`${uid}-heading`}>
 <Card><CardHeader><CardTitle><h2 id={`${uid}-heading`}>Share selected work</h2></CardTitle><p>Choose what an agent may read or return. Choose an expiry within 24 hours.</p><Badge variant="outline">{adapter.available?'Service connected':'Not connected'}</Badge></CardHeader><CardContent>
 {!adapter.available&&<p role="status">{adapter.unavailableReason}</p>}{!canExport&&<p>Separate export authority is required; squad read access is not permission to delegate.</p>}
 <form onSubmit={e=>{e.preventDefault();if(!error)void mutate(()=>adapter.issue(prepareDelegation(draft,recipients)))}}>
 <fieldset disabled={pending}><legend>Recipient and scope</legend>
 <label>Recipient<select required value={draft.recipientId} onChange={e=>update({recipientId:e.target.value})}><option value="">Choose an agent</option>{(['cloud','local'] as const).map(location=><optgroup key={location} label={location==='cloud'?'Cloud recipients':'Local recipients'}>{recipients.filter(r=>r.location===location).map(r=><option key={r.id} value={r.id}>{r.label} · {r.id}</option>)}</optgroup>)}</select></label>
 {!recipients.length&&<p>No recipient identities supplied. Registration does not prove live reachability.</p>}
 <label>Work type<select value={draft.kind} onChange={e=>update({kind:e.target.value as ResourceKind,resource:'',operations:[],acknowledged:false})}>{!kinds.length&&<option value="task">No registered work</option>}{kinds.map(kind=><option key={kind} value={kind}>{kind==='skill'?'SKILL.md':kind==='workspace'?'Named project workspace':kind}</option>)}</select></label>
 <label>{draft.kind==='prompt'?'Exact prompt content':'Work to share'}{resources?<select required value={draft.resource} onChange={e=>update({resource:e.target.value,acknowledged:false})}><option value="">Choose work</option>{resources.filter(r=>r.kind===draft.kind).map(r=><option key={r.id} value={r.id}>{r.id}</option>)}</select>:<textarea required rows={4} value={draft.resource} onChange={e=>update({resource:e.target.value,acknowledged:false})}/>}</label>
 <p>Only the selected work is shared. Files outside this selection stay private.</p>
 </fieldset>
 <fieldset disabled={pending}><legend>Permissions</legend>{(['read','submit-result'] as const).map(op=><label className="external-delegation-check" key={op}><input type="checkbox" disabled={!operations.includes(op==='read'?'read':'submit')||(op==='submit-result'&&draft.kind!=='task')} checked={draft.operations.includes(op)} onChange={e=>update({operations:e.target.checked?[...draft.operations,op]:draft.operations.filter(o=>o!==op),acknowledged:false})}/>{op==='read'?'Read selected content':'Submit scoped results / progress'}</label>)}
 <label>Expires after<select value={draft.expiryHours} onChange={e=>update({expiryHours:Number(e.target.value),acknowledged:false})}><option value={1}>1 hour</option><option value={4}>4 hours</option><option value={24}>24 hours · workspace review</option></select></label></fieldset>
 <aside aria-label="Disclosure preview"><h3>Review what you will share</h3><p>Included: {draft.kind} · {draft.recipientId||'no recipient'} · {draft.operations.join(', ')||'no operations'} · {draft.expiryHours} hours from issuance</p><pre>{draft.resource||'No content selected'}</pre><h4>Exact resource manifest</h4>{manifest?<><p>Coverage: {manifest.coverage} · {manifest.complete?'No recorded omissions in this scope':'Incomplete coverage; exclusions below'}. Excluded directories are opaque subtrees, not enumerated descendants.</p><h5>Included files</h5><ul>{manifest.files.map(f=><li key={f.path}>{f.path} · {f.size_bytes} bytes · SHA-256 {f.sha256}</li>)}</ul><h5>Excluded paths</h5><ul>{manifest.excluded.map(f=><li key={f.path}>{f.path} · {f.reason}</li>)}</ul></>:<p>{draft.kind==='workspace'?'No exact file manifest available.':'This resource is not a workspace file export.'}</p>}<h4>Always excluded</h4><ul>{exclusions.map(x=><li key={x}>{x}</li>)}</ul><p>No implicit write, execution, re-delegation or terminal/desktop access. The service checks access before anything is shared.</p><p>{disclosureWarning}</p></aside>
 <label className="external-delegation-check"><input type="checkbox" checked={draft.acknowledged} onChange={e=>update({acknowledged:e.target.checked})}/>I confirm intended disclosure, exclusions and irreversible copying risk.</label>
 {error&&<p>{error}</p>}<Button type="submit" disabled={!enabled||!!error}>{pending?'Sharing…':'Share selected work'}</Button>
 </form><p role="status" aria-live="polite">{message}</p>
 </CardContent></Card>
 <Card><CardHeader><CardTitle><h3>Shared access</h3></CardTitle><Button type="button" variant="outline" disabled={!adapter.available||pending} onClick={()=>void refresh()}>Refresh access records</Button></CardHeader><CardContent>
 {!records.length&&<p>Access records have not been loaded. Refresh to check existing shares.</p>}
 <ul className="external-delegation-records">{records.map(record=><li key={record.id}><Badge variant="outline">{delegationState(record,now)}</Badge><strong>{record.recipientId}</strong><ul aria-label="Granted resources">{(record.resources??[`${record.kind}:${record.resource}`]).map(resource=><li key={resource}>{resource}</li>)}</ul><p>Grant {record.id} · Issuer {record.issuer} · expires {record.expiresAt}</p><p>{(record.grantedOperations??record.operations).join(', ')}</p>{uncertainRevokes.includes(record.id)&&<><p>Revocation outcome unresolved for this exact grant.</p><Button disabled={pending||!adapter.inspect} onClick={()=>void reconcileRevoke(record.id)}>Inspect exact revocation outcome</Button></>}{delegationState(record,now)==='active'&&(revokeId===record.id?<div><p>{disclosureWarning}</p><Button type="button" variant="destructive" disabled={!managementEnabled||uncertainRevokes.includes(record.id)} onClick={()=>void mutate(()=>adapter.revoke(record.id),record.id)}>Confirm revoke future access</Button><Button type="button" variant="ghost" onClick={()=>setRevokeId('')}>Cancel</Button></div>:<Button type="button" variant="outline" disabled={!managementEnabled||uncertainRevokes.includes(record.id)} onClick={()=>setRevokeId(record.id)}>Revoke…</Button>)}</li>)}</ul>
 {adapter.audit&&records.map(record=><DelegationAudit key={record.id} adapter={adapter} grantId={record.id}/>)}
 <p>Authorized squad observers may see scoped progress, access records and results, not private reasoning or unrelated personal activity. Access history below is an explicit metadata snapshot, not a live subscription or complete pre-migration history.</p>
 </CardContent></Card></section>;
}
