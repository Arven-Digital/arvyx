import React,{useState} from 'react';
import {Button} from './vendor/components/ui/button';
type Request=(path:string,body?:unknown)=>Promise<any>;
type Adapter={id:string;label:string};
const FALLBACK_ADAPTERS:Adapter[]=[{id:'hermes',label:'Hermes'}];
export function LocalOnboardingControls({request,onRefresh,pairing,busy,perform,adapters}:{request:Request;onRefresh:()=>Promise<void>;pairing:boolean;busy:boolean;perform:(action:()=>Promise<void>)=>void;adapters?:Adapter[]}){
 const options=(Array.isArray(adapters)?adapters.filter(a=>a&&typeof a.id==='string'&&a.id&&typeof a.label==='string'):[]);
 const choices=options.length?options:FALLBACK_ADAPTERS;
 const [family,setFamily]=useState(choices[0].id),[path,setPath]=useState(''),[agent,setAgent]=useState(''),[consent,setConsent]=useState(false),[ticket,setTicket]=useState<any>(null),[claims,setClaims]=useState<any[]>([]),[approved,setApproved]=useState<Record<string,boolean>>({});
 const selected=choices.some(a=>a.id===family)?family:choices[0].id;
 return <section aria-label="Manual location and remote pairing">
 <h3>Connect an exact local profile</h3><p>Choose the harness, then enter an existing registered agent ID and the exact directory: a Hermes profile directory, or the Claude Code (~/.claude) or Codex (~/.codex) state root. This opens read-only session metadata from file names and timestamps. It does not start the harness, read transcripts, import identity, or elect a live main agent.</p>
 <label>Harness<select value={selected} onChange={e=>{setFamily(e.target.value);setConsent(false)}}>{choices.map(a=><option key={a.id} value={a.id}>{a.label}</option>)}</select></label>
 <label>Immutable agent ID<input value={agent} onChange={e=>{setAgent(e.target.value);setConsent(false)}}/></label>
 <label>Absolute profile directory<input value={path} onChange={e=>{setPath(e.target.value);setConsent(false)}} placeholder="/absolute/path/to/profile"/></label>
 <label><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)}/>Allow metadata access to this exact profile for this registered agent</label>
 <Button disabled={busy||!agent||!path||!consent} onClick={()=>perform(async()=>{await request('/manual/connect',{family:selected,path,agent_id:agent,confirmed:true});setConsent(false);await onRefresh()})}>Connect profile metadata</Button>
 <h3>Pair a remote machine</h3><p>Pairing enrolls an Ed25519 identity. It grants no task, workspace, provider or root execution authority. Use an approved SSH tunnel to reach this loopback listener.</p>
 {!pairing?<p>Pairing unavailable: start this listener with explicit pairing enabled and the approved cryptography extra installed.</p>:<>
 <Button disabled={busy} onClick={()=>perform(async()=>setTicket(await request('/pairing/issue',{confirmed:true})))}>Issue single-use pairing code</Button>
 {ticket&&<div><p>Expires: {new Date(ticket.expires_at*1000).toLocaleString()}</p><p>On the intended remote machine, run:</p><pre>{`amc -confirm ${ticket.code} --url http://127.0.0.1:${location.port} --name REMOTE_NAME`}</pre><p>Compare the public fingerprint through a trusted channel before approving below.</p></div>}
 <Button disabled={busy} onClick={()=>perform(async()=>{setApproved({});const result=await request('/pairing/pending');if(!Array.isArray(result.claims)||result.claims.some((c:any)=>typeof c.claim_id!=='string'||!c.claim_id||typeof c.fingerprint!=='string'||typeof c.name!=='string'||!Number.isFinite(c.expires))||new Set(result.claims.map((c:any)=>c.claim_id)).size!==result.claims.length)throw Error('Exact pending claim identities unavailable.');setClaims(result.claims)})}>Refresh pending claims</Button>
 {claims.map(claim=><article key={claim.claim_id}><strong>{claim.name}</strong><code>{claim.fingerprint}</code><p>Claim {claim.claim_id} · Expires: {new Date(claim.expires*1000).toLocaleString()}</p><label><input type="checkbox" checked={!!approved[claim.claim_id]} onChange={e=>setApproved({...approved,[claim.claim_id]:e.target.checked})}/>I compared this exact fingerprint and reviewed this claim's name and expiry</label><Button disabled={busy||!approved[claim.claim_id]} onClick={()=>perform(async()=>{await request('/pairing/decide',{fingerprint:claim.fingerprint,claim_id:claim.claim_id,approved:true,confirmed:true});setApproved({});setClaims(cs=>cs.filter(c=>c.claim_id!==claim.claim_id))})}>Approve this claim</Button><Button disabled={busy} onClick={()=>perform(async()=>{await request('/pairing/decide',{fingerprint:claim.fingerprint,claim_id:claim.claim_id,approved:false,confirmed:true});setApproved({});setClaims(cs=>cs.filter(c=>c.claim_id!==claim.claim_id))})}>Deny this claim</Button></article>)}
 </>}
 </section>
}
