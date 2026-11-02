import React, {useEffect, useState} from 'react';
import {workspaceRequest} from './workspace-request';
type NativeFacts = {session:string; host:string; tool:string; conversation:string; pid:number};
type Agent = {id:string; display_name?:string; machine_id:string; runtime_id:string; harness:string|null; machine_valid:boolean};
type Binding = NativeFacts & {agent_id:string; revision:number};
type State = {sessions:NativeFacts[]; agents:Agent[]; bindings:Binding[]};
const compatible = (a:Agent, s:NativeFacts) => a.machine_valid && a.machine_id===s.host && a.harness===s.tool;
export function LocalBinding({capability,onBound}:{capability:string;onBound:()=>void}) {
 const [state,setState]=useState<State|null>(null), [error,setError]=useState('');
 const [choice,setChoice]=useState<Record<string,string>>({}), [names,setNames]=useState<Record<string,string>>({});
 const [busy,setBusy]=useState(false);
 async function read():Promise<State> {
  const r=await fetch('/api/local-bindings',workspaceRequest(capability));
  if(!r.ok) throw Error('Binding facts unavailable');
  return r.json();
 }
 async function load() {
  setError(''); setBusy(true);
  try {setState(await read()); setChoice({});}
  catch(e) {setState(null); setError(String(e));}
  finally {setBusy(false);}
 }
 useEffect(()=>{void load();},[capability]);
 async function post(path:string, body:unknown) {
  const r=await fetch(path,{...workspaceRequest(capability),method:'POST',headers:{...workspaceRequest(capability).headers,'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await r.json(); if(!r.ok) throw Error(data.error); return data;
 }
 async function enroll(s:NativeFacts) {
  setError(''); setBusy(true);
  try {
   const result=await post('/api/local-enrollments',{...s,display_name:names[s.session]?.trim()});
   const next=await read();
   if(!next.agents.some(a=>a.id===result.agent.id&&compatible(a,s))) throw Error('Registration readback failed; refresh before retrying');
   setState(next); setNames({...names,[s.session]:''});
   // Registration never chooses or binds the new identity on the user's behalf.
  } catch(e) {setError(String(e));} finally {setBusy(false);}
 }
 async function bind(s:NativeFacts) {
  setError(''); setBusy(true);
  try {
   const agent_id=choice[s.session];
   await post('/api/local-bindings',{...s,agent_id,revision:state?.bindings.find(b=>b.session===s.session)?.revision??0});
   const next=await read();
   if(!next.bindings.some(b=>b.session===s.session&&b.agent_id===agent_id)) throw Error('Binding readback failed');
   setState(next); onBound();
  } catch(e) {setError(String(e));} finally {setBusy(false);}
 }
 return <section className="local-binding" aria-label="Native conversation identity binding"><h2>Bind an existing native conversation</h2>
  <p>Human assertion only. No input, restart, takeover or model call. Register a fresh identity if needed, then explicitly select and confirm it. Main agent covers the whole Cockpit; only the user changes it. Disconnect retains the selection.</p>
  {error&&<p role="alert">{error}</p>}
  {state?.sessions.map(s=><div key={s.session}>
   <dl>{Object.entries(s).map(([k,v])=><React.Fragment key={k}><dt>{k}</dt><dd>{String(v)}</dd></React.Fragment>)}</dl>
   <label>Registered agent identity<select disabled={busy} value={choice[s.session]??''} onChange={e=>setChoice({...choice,[s.session]:e.target.value})}>
    <option value="">Choose identity — never inferred</option>
    {state.agents.map(a=><option key={a.id} value={a.id} disabled={!compatible(a,s)}>{a.display_name??a.id} · ID {a.id} · host {a.machine_id} · runtime {a.runtime_id} ({a.harness??'unknown'}){!compatible(a,s)?' — incompatible host/runtime':''}</option>)}
   </select></label>
   <button disabled={busy||!state.agents.some(a=>a.id===choice[s.session]&&compatible(a,s))} onClick={()=>void bind(s)}>Confirm human identity binding</button>
   {!state.agents.some(a=>compatible(a,s))&&<p role="status">No compatible registry identity. Register a new identity below; existing actors are never rewritten.</p>}
   <fieldset disabled={busy}><legend>Register a fresh local identity</legend>
    <p>Creates new AMC agent and runtime IDs for this exact host and harness, with no permissions or provider credentials. Does not bind, select a main agent, launch a profile, or copy identity/history.</p>
    <label>New identity display name<input maxLength={128} value={names[s.session]??''} onChange={e=>setNames({...names,[s.session]:e.target.value})}/></label>
    <button disabled={!names[s.session]?.trim()} onClick={()=>void enroll(s)}>Register new local identity</button>
   </fieldset>
  </div>)}
  <button disabled={busy} onClick={()=>void load()}>Refresh binding facts</button>
 </section>;
}
