import React,{useState} from 'react';
import {AgentIdentity} from './LocalIdentity';
import {Card,CardHeader,CardContent} from './vendor/components/ui/card';
import './TeamView.css';
type Agent={id:string;display_name?:string;status?:string;machine?:string};
type Task={id:string;title:string;owner?:string;status?:string};
type TeamSnapshot={team?:{availability?:Record<string,boolean>;control?:{agents?:Agent[];source?:{bounds?:{agents_discovered?:number;agents_returned?:number;agents_invalid?:number;agents_truncated?:boolean}}};tasks?:{tasks?:Task[]}}};
const closed=new Set(['completed','done','cancelled','retired']);
export function TeamView({snapshot,onAgentTasks,onTask}:{snapshot:TeamSnapshot;onAgentTasks:(id:string)=>void;onTask:(id:string)=>void}){
 const [query,setQuery]=useState('');
 const availability=snapshot.team?.availability??{};
 const agents=availability.control===true?snapshot.team?.control?.agents??[]:[];
 const bounds=snapshot.team?.control?.source?.bounds;
 const membershipComplete=availability.control===true&&bounds?.agents_truncated===false&&bounds.agents_invalid===0&&bounds.agents_returned===agents.length&&bounds.agents_discovered===agents.length;
 const tasks=availability.tasks===true?snapshot.team?.tasks?.tasks??[]:[];
 const open=tasks.filter(t=>!closed.has(t.status??''));
 const unassigned=availability.control===true?open.filter(t=>!t.owner||!agents.some(a=>a.id===t.owner)):[];
 const visible=agents.filter(a=>`${a.display_name??''} ${a.id} ${a.machine??''}`.toLowerCase().includes(query.toLowerCase()));
 return <section className="team-view" aria-label="Team overview">
  <div className="team-heading"><div><span className="team-eyebrow">WORKFORCE OVERVIEW</span><h2>Your team, at a glance</h2><p>People, ownership and work that needs attention.</p></div><span className="team-readonly">Read-only overview</span></div>
  <div className="team-metrics">
   {[['Returned agents',availability.control===true?agents.length:'Unavailable'],['Open tasks',availability.tasks===true?open.length:'Unavailable'],['Needs attention',availability.tasks===true?open.filter(t=>t.status==='blocked'||t.status==='review').length:'Unavailable']].map(([label,value])=><Card key={label}><CardContent><span>{label}</span><strong>{value}</strong></CardContent></Card>)}
  </div>
  <div className="team-directory-heading"><h3>Agent directory</h3><label>Find an agent<input type="search" aria-label="Find an agent" placeholder="Name, ID or machine" value={query} onChange={e=>setQuery(e.target.value)}/></label></div>
  <p className="team-note">Registry presence is not live reachability. Statuses below describe coordination workload, not registry status or heartbeat reachability.</p>
  {availability.control===true&&<p className="team-note" role="status">{membershipComplete?'Registry membership complete.':'Registry membership incomplete or completeness unknown.'} {agents.length} returned{typeof bounds?.agents_discovered==='number'?`; ${bounds.agents_discovered} discovered`: ''}.</p>}
  {!availability.control?<p role="status">Registry unavailable or unauthorized. Agent membership cannot be confirmed.</p>:!agents.length?<p>No registered agents returned.</p>:!visible.length?<p>No agents match your search.</p>:<div className="team-agent-grid">{visible.map(a=>{
   const assigned=tasks.filter(t=>t.owner===a.id);const active=assigned.filter(t=>!closed.has(t.status??''));
   return <Card key={a.id} className="team-agent"><CardHeader><div className="team-agent-heading"><AgentIdentity agent={{id:a.id,name:a.display_name??a.id}} size="lg"/><span className="team-status">Coordination workload: {a.status??'Not reported'}</span></div><span className="team-id">{a.id}</span></CardHeader><CardContent><dl><div><dt>Machine</dt><dd>{a.machine??'Not reported'}</dd></div><div><dt>Open / total tasks</dt><dd>{availability.tasks===true?`${active.length} / ${assigned.length}`:'Unavailable'}</dd></div></dl>
   <div className="team-work"><h4>Current work</h4>{!availability.tasks?<p>Task authority unavailable.</p>:!active.length?<p>No open tasks assigned.</p>:<ul>{active.slice(0,3).map(t=><li key={t.id}><button onClick={()=>onTask(t.id)}>{t.title||t.id}</button><span>{t.status??'Unknown'}</span></li>)}</ul>}{active.length>3&&<p>+{active.length-3} more open tasks</p>}</div>
   <button className="team-task-link" disabled={!availability.tasks} onClick={()=>onAgentTasks(a.id)}>View assigned tasks <span aria-hidden="true">→</span></button></CardContent></Card>;
  })}</div>}
  <div className="team-bottom"><Card><CardHeader><h3>{availability.control===true?(membershipComplete?'Work without a registered owner':'Unassigned work / owner membership unknown'):'Ownership unknown'}</h3></CardHeader><CardContent>{!availability.tasks?<p>Task authority unavailable or unauthorized. Workload cannot be confirmed.</p>:availability.control!==true?<p>Ownership unknown while registry unavailable. Registered ownership cannot be confirmed.</p>:!tasks.length?<p>No tasks returned.</p>:!unassigned.length?<p>{membershipComplete?'All open tasks have a registered owner.':'All open task owners appear in the returned registry.'}</p>:<ul className="team-unassigned">{unassigned.map(t=><li key={t.id}><div><button onClick={()=>onTask(t.id)}>{t.title||t.id}</button><small>{t.owner?membershipComplete?`Owner outside returned registry: ${t.owner}`:`Owner membership unknown: ${t.owner}`:'Unassigned'}</small></div><span className="team-status">{t.status??'Unknown'}</span></li>)}</ul>}</CardContent></Card>
  <Card><CardHeader><h3>Authority connections</h3></CardHeader><CardContent><ul className="team-connections">{[['control','Agent registry'],['tasks','Task ledger'],['approvals','Approvals'],['handoffs','Handoffs'],['threads','Coordination threads']].map(([key,label])=><li key={key}><span>{label}</span><span className={availability[key]===true?'team-available':'team-unavailable'}>{availability[key]===true?'Available':'Unavailable'}</span></li>)}</ul><p className="team-note">AMC permissions remain authoritative. This view does not dispatch actions or change agent lifecycle.</p></CardContent></Card></div>
 </section>;
}
