import React,{useState,useEffect,useRef} from 'react';
import {createRoot} from 'react-dom/client';
import {KanbanBoard} from './vendor/components/KanbanBoard';
import {AgentIdentity} from './LocalIdentity';
import {applyIssueFilters,defaultIssueFilterState} from './vendor/lib/issue-filters';
import {adapt} from './adapter';
import {TaskComposer} from './TaskComposer';
import {LocalBinding} from './LocalBinding';
import {PrimaryAgentControl} from './PrimaryAgentControl';
import {TeamView} from './TeamView';
import {ConnectionOnboarding,type WorkspaceMode} from './ConnectionOnboarding';
import {connectLocalWorkspace,consumeLocalLaunchCapability} from './local-workspace';
import {PublicOnboarding} from './PublicOnboarding';
import {ExternalAuthorityPanel} from './ExternalAuthorityPanel';
import {connectSnapshot} from './connection';
import {readRoute,taskRoute} from './navigation';
import './vendor/index.css';
import './style.css';
export function App(){
 const connectionGeneration=useRef(0);
 const [handoff,setHandoff]=useState(()=>consumeLocalLaunchCapability(location,(...args)=>history.replaceState(...args)));
 const [key,setKey]=useState('');const [snapshot,setSnapshot]=useState<any>(null);const [error,setError]=useState('');const [page,setPage]=useState(()=>new URLSearchParams(location.hash.slice(1)).get('page')==='external-delegation'?'External delegation':'Tasks');const [agent,setAgent]=useState('');const [project,setProject]=useState('');const [query,setQuery]=useState('');const [detail,setDetail]=useState('');
 const [connectionMode,setConnectionMode]=useState<WorkspaceMode>('workspace');
 const [presentationMode,setPresentationMode]=useState<'unknown'|'real-local'|'workspace'|'explore'>('unknown');
 useEffect(()=>{let active=true;fetch('/api/presentation-mode').then(async r=>r.ok?(await r.json()).mode:'unknown').then(mode=>{if(active)setPresentationMode(mode==='real-local'||mode==='workspace'||mode==='explore'?mode:'unknown')}).catch(()=>{if(active)setPresentationMode('unknown')});return ()=>{active=false;connectionGeneration.current++}},[]);
 const [synthetic]=useState(()=>readRoute(location.hash).synthetic);
 useEffect(()=>{const listener=()=>{const route=readRoute(location.hash);setDetail(route.task);if(route.task)setPage('Tasks');else if(new URLSearchParams(location.hash.slice(1)).get('page')==='external-delegation')setPage('External delegation')};listener();window.addEventListener('hashchange',listener);return ()=>window.removeEventListener('hashchange',listener)},[]);
 async function refresh(e?:any){e?.preventDefault();const generation=++connectionGeneration.current;setError('');try{const next=await (connectionMode==='real-local'?connectLocalWorkspace(key):connectSnapshot(key));if(generation===connectionGeneration.current)setSnapshot(next)}catch(e:any){if(generation===connectionGeneration.current){setSnapshot(null);setError(e.message)}}}
 const model=snapshot?adapt(snapshot):{issues:[],agents:[],sessions:[]};
 const projects=[...new Set(model.sessions.map((s:any)=>s.project))] as string[];
 const agents=[...new Set([...model.agents.map((a:any)=>a.id),...model.issues.map((t:any)=>t.assigneeAgentId).filter(Boolean)])] as string[];
 const filtered=applyIssueFilters(model.issues,{...defaultIssueFilterState,assignees:agent?[agent]:[],projects:project?[project]:[]}).filter((t:any)=>(t.title+' '+t.id).toLowerCase().includes(query.toLowerCase()));
 const chosen=model.issues.find((t:any)=>t.id===detail);
 const composer=page==='Tasks'&&snapshot?<TaskComposer capability={key} available={snapshot.team.availability?.tasks===true} onCreated={()=>refresh()}/>:null;
 return <div className="layout">
 <aside><strong aria-label="Arvyx" style={{fontSize:28,letterSpacing:"-.04em"}}>Arvyx</strong><p>Control room</p>
 {['Team','Agents','Projects','Tasks','External delegation'].map(p=><button aria-current={page===p?'page':undefined} onClick={()=>{setPage(p);setDetail('');const params=new URLSearchParams();if(synthetic)params.set('preview','synthetic');if(p==='External delegation')params.set('page','external-delegation');location.hash=params.toString()}} key={p}>{p}</button>)}
 <small>Local control room<br/>Workspace access stays separate</small></aside>
 <main>{presentationMode==='explore'&&<section aria-label="Explore before enrollment"><h2>Your local control room</h2><p>Explore the interface and skip organizer setup. No agent or native owner is connected.</p><details><summary>Set up this machine when ready</summary><p>Use the explicit local enrollment command to create a new private home and machine identity, then configure the local owner. Existing pilot state needs a separate reviewed adoption. No provider starts during enrollment.</p><code>python3 -m arvyx_control.machine_enrollment --help</code></details></section>}<header><h1>{page}</h1>{snapshot&&<button onClick={()=>refresh()}>Refresh snapshot</button>}</header>
 {page!=='External delegation'&&presentationMode!=='explore'&&<ConnectionOnboarding connectionGeneration={connectionGeneration} fixtureOnly={import.meta.env.VITE_AMC_FIXTURE_ONLY==='true'} syntheticPreview={synthetic} hostname={location.hostname} initialCredential={handoff} connected={snapshot!==null} connectionMode={connectionMode} onConnected={(next,capability,mode)=>{setHandoff('');setConnectionMode(mode);setKey(capability);setSnapshot(next);setError('')}} onDisconnect={()=>{connectionGeneration.current++;setHandoff('');setKey('');setSnapshot(null);setConnectionMode('workspace');setError('');setAgent('');setProject('');setDetail('')}}/>}
 {page!=='External delegation'&&presentationMode!=='unknown'&&presentationMode!=='explore'&&!handoff&&<PublicOnboarding key={key} capability={key} presentationMode={presentationMode}/>}
 {connectionMode==='real-local'&&page!=='External delegation'&&<p role="note">Connected to the existing local owner. Agent setup shares this authenticated service. Profile metadata and instruction-copy review do not start runtimes or grant execution authority.</p>}
 {synthetic&&connectionMode!=='real-local'&&page!=='External delegation'&&<p role="note">Test demo · Sample tasks and agents, not live activity.</p>}
 {page!=='External delegation'&&error&&<p role="alert">{error}</p>}
 {page==='External delegation'&&(presentationMode==='unknown'?<p role="status">Checking presentation capabilities…</p>:presentationMode==='real-local'||connectionMode==='real-local'?<ExternalAuthorityPanel capability={key||handoff} realLocal/>:<ExternalAuthorityPanel/>)}
 {page!=='External delegation'&&(snapshot?<>
 <p role="status">{connectionMode==='real-local'?'Real local owner snapshot (record provenance unverified; may include synthetic or scratch records)':connectionMode==='synthetic'?'Synthetic fixture snapshot':'Authoritative snapshot'} · {snapshot.local.host??'local'} · {model.issues.length} tasks · {model.sessions.length} sessions</p>
 <p>Dragging a card never updates AMC. Status lanes are presentation mappings, not lifecycle changes.</p>
 {connectionMode==='real-local'&&<LocalBinding capability={key} onBound={()=>refresh()}/>}
 <PrimaryAgentControl key={key} capability={key} refreshToken={snapshot}/>
 {page==='Team'&&<TeamView snapshot={{...snapshot,team:{...snapshot.team,control:{...snapshot.team.control,agents:(snapshot.team.control?.agents??[]).map((a:any)=>({...a,machine:typeof a.machine==='string'?a.machine:a.machine?.display_name??a.machine?.id}))}}}} onAgentTasks={id=>{setAgent(id);setProject('');setQuery('');setPage('Tasks')}} onTask={id=>{setDetail(id);setAgent('');setProject('');setQuery('');setPage('Tasks');location.hash=taskRoute(id,synthetic)}}/>}
 {page==='Agents'&&<section>{agents.map(id=><button key={id} onClick={()=>{setAgent(id);setPage('Tasks')}}><AgentIdentity agent={{id,name:model.agents.find((a:any)=>a.id===id)?.display_name??id}}/> View assigned tasks</button>)}</section>}
 {page==='Projects'&&<section>{projects.map(p=><button key={p} onClick={()=>{setProject(p);setPage('Tasks')}}>{p} · {model.sessions.filter((s:any)=>s.project===p).length} sessions</button>)}</section>}
 {page==='Tasks'&&<>
 {composer}
 <div className="filters"><label>Agent <select aria-label="Agent" value={agent} onChange={e=>setAgent(e.target.value)}><option value="">All agents</option>{agents.map(id=><option key={id}>{id}</option>)}</select></label>
 <label>Project <select aria-label="Project" value={project} onChange={e=>setProject(e.target.value)}><option value="">All projects</option>{projects.map(p=><option key={p}>{p}</option>)}</select></label>
 <input aria-label="Search tasks" placeholder="Search title or exact ID" value={query} onChange={e=>setQuery(e.target.value)}/><button onClick={()=>{setAgent('');setProject('');setQuery('')}}>Reset filters</button><output>{filtered.length} matching tasks</output></div>
 <div className="board"><KanbanBoard issues={filtered} agents={agents.map(id=>({id,name:id}))} onUpdateIssue={()=>setError('No drag mutation dispatched. Use explicit governed actions.')}/></div>
 {chosen&&<section aria-label="Task details"><h2>{chosen.title}</h2><p>ID: {chosen.id} · AMC status: {chosen.rawStatus} · Owner: {chosen.assigneeAgentId??'unassigned'}</p><p>Project: {chosen.projectId??'unbound'}</p><button onClick={()=>{setDetail('');location.hash=taskRoute('',synthetic)}}>Close details</button></section>}
 </>}
 </>:null)}
 </main></div>;
}
if(typeof document!=='undefined'){
 const root=document.getElementById('root');
 if(root)createRoot(root).render(<App/>);
}
