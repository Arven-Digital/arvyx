import React,{useEffect,useRef,useState} from 'react';
import {getPrimary,setPrimary,type PrimaryState} from './primary-agent';
export function PrimaryAgentControl({capability,refreshToken}:{capability:string;refreshToken?:unknown}){
 const [state,setState]=useState<PrimaryState|null>(null);
 const [busy,setBusy]=useState(true);const [error,setError]=useState('');
 const [context,setContext]=useState<string|null>(null);const actions=useRef(new Map<string,HTMLDetailsElement>());
 const generation=useRef(0);const inFlight=useRef(false);const operation=useRef(false);const [changing,setChanging]=useState(false);const [retry,setRetry]=useState(0);
 useEffect(()=>{const id=++generation.current;setState(null);setBusy(true);setError('');inFlight.current=true;
 getPrimary(capability).then(value=>{if(id===generation.current)setState(value)}).catch(()=>{if(id===generation.current)setError('Primary-agent authority unavailable or unauthorized. No selection inferred.')}).finally(()=>{if(id===generation.current){setBusy(false);inFlight.current=false}});
 return()=>{generation.current++};},[capability,refreshToken,retry]);
 async function choose(agentId:string){
  if(operation.current||inFlight.current||!state?.can_set_primary)return;
  operation.current=true;setChanging(true);const id=generation.current;setBusy(true);setError('');
  actions.current.forEach(el=>el.open=false);setContext(null);
  try{const next=await setPrimary(capability,agentId,state.revision);if(id===generation.current)setState(next)}
  catch{if(id===generation.current){setState(null);setError('Change refused or unconfirmed. Refresh primary status before another action. Nothing is retried.')}}
  finally{operation.current=false;setChanging(false);if(id===generation.current){setBusy(false)}else{generation.current++;inFlight.current=false;setBusy(false);setState(null);setError('Change settled after refresh. Refresh primary status before another action. Nothing is retried.')}}
 }
 return <section aria-label="Primary agent" className="primary-agent-control" aria-busy={busy}>
  <h2>Global manager · Ana ajan</h2>
  <p>Only you can change the primary agent. Disconnecting never transfers this selection. Model roles do not promote agents.</p>
  {busy&&<p role="status">Loading primary-agent authority…</p>}
  {error&&<p role="alert">{error}</p>}
  {!busy&&<button onClick={()=>setRetry(retry+1)}>Refresh primary status</button>}
  {state&&!busy&&<>
   <p role="status">{state.primary_agent_id?<>Ana ajan: <strong>{state.agents.find(a=>a.id===state.primary_agent_id)?.display_name??state.primary_agent_id}</strong> · {state.primary_connected?'Connected':'Offline · selection retained'}</>:'No primary agent selected by authority.'}</p>
   {!state.can_set_primary&&<p>Read-only access. Changing the primary agent requires user authority.</p>}
   {!state.agents.length&&<p>No agents returned by primary authority.</p>}
   <ul>{state.agents.map(a=><li key={a.id} onContextMenu={event=>{event.preventDefault();setContext(a.id);const el=actions.current.get(a.id);if(el){el.open=true;requestAnimationFrame(()=>el.querySelector('button')?.focus())}}}>
    <span>{a.display_name??a.id} · {a.id} · {a.connected?'Connected':'Offline'}{a.id===state.primary_agent_id?' · Ana ajan':''}</span>
    <details ref={el=>{if(el)actions.current.set(a.id,el);else actions.current.delete(a.id)}} open={context===a.id?true:undefined} onKeyDown={e=>{if(e.key==='Escape'){e.currentTarget.open=false;setContext(null);e.currentTarget.querySelector('summary')?.focus()}}}>
     <summary aria-label={`Agent actions: ${a.display_name??a.id}`}>Agent actions</summary>
     <button disabled={!state.can_set_primary||!a.connected||a.id===state.primary_agent_id||busy||changing} onClick={()=>choose(a.id)}>Ana ajan yap</button>
     {!a.connected&&<small>Reconnect before selecting this agent.</small>}
    </details>
   </li>)}</ul>
  </>}
 </section>;
}
