import React,{useState} from 'react';
import {Button} from './vendor/components/ui/button';
import type {Target} from './public-onboarding';

type Request=(path:string,body?:unknown)=>Promise<any>;
type Root={id:string;label:string};
export function WorkspaceReview({workspace,onConfirm,onCancel,busy=false}:{workspace:string;onConfirm:()=>void;onCancel:()=>void;busy?:boolean}){
 return <section aria-label="Review workspace preparation"><h4>Prepare this workspace</h4><p>{workspace}</p><p>No native session or process will start. Runtime launch needs a separately approved executor.</p><Button disabled={busy} onClick={onConfirm}>Prepare this exact workspace</Button><Button disabled={busy} variant="outline" onClick={onCancel}>Cancel</Button></section>
}
export function SessionPreparation({target,request}:{target:Target;request:Request}){
 const [roots,setRoots]=useState<Root[]|null>(null),[root,setRoot]=useState(''),[mode,setMode]=useState('existing'),[path,setPath]=useState(''),[session,setSession]=useState(''),[preview,setPreview]=useState<any>(null),[busy,setBusy]=useState(false),[message,setMessage]=useState(''),[error,setError]=useState('');
 async function run(work:()=>Promise<void>){if(busy)return;setBusy(true);setError('');try{await work()}catch(e){setError(e instanceof Error?e.message:'Workspace unavailable.')}finally{setBusy(false)}}
 function invalidate(){setPreview(null);setMessage('')}
 return <section aria-label="Prepare a New session workspace"><h4>Workspace for a New session</h4><p>Choose an existing folder, the recorded folder of an exact session, or a new private folder. This prepares the workspace; it does not create a native conversation.</p>
 {!roots&&<Button disabled={busy} onClick={()=>run(async()=>{const result=await request('/sessions/workspaces',{target});setRoots(result.roots)})}>Load authorized workspace roots</Button>}
 {roots&&<><label>Authorized root<select disabled={busy} value={root} onChange={e=>{setRoot(e.target.value);invalidate()}}><option value="">Choose a root</option>{roots.map(r=><option key={r.id} value={r.id}>{r.label}</option>)}</select></label>{!roots.length&&<p>No workspace roots are configured by your local operator.</p>}
 <label>Workspace choice<select disabled={busy} value={mode} onChange={e=>{setMode(e.target.value);invalidate()}}><option value="existing">Use an existing folder</option><option value="current">Use an exact session’s recorded workspace</option><option value="create">Create a new private folder</option></select></label>
 {mode==='current'?<label>Exact stored session ID<input disabled={busy} value={session} onChange={e=>{setSession(e.target.value);invalidate()}}/></label>:<label>Folder relative to the root<input disabled={busy} value={path} onChange={e=>{setPath(e.target.value);invalidate()}} placeholder="research"/></label>}
 <p>Metadata preparation only. Sandbox, host and root execution require an approved executor and fresh execution consent.</p>
 <Button disabled={busy||!root||!(mode==='current'?session:path)} onClick={()=>run(async()=>{const workspace={mode,root_id:root,...(mode==='current'?{session_id:session}:{path})};setPreview(await request('/sessions/prepare',{target,workspace,environment:'metadata'}))})}>Review workspace</Button></>}
 {preview&&<WorkspaceReview workspace={preview.workspace} busy={busy} onCancel={()=>setPreview(null)} onConfirm={()=>run(async()=>{const result=await request('/sessions/commit',{consent_id:preview.consent_id,consent_sha256:preview.sha256,confirmed:true});if(result.status!=='workspace_ready'||result.native_session_created!==false||result.execution!==false)throw Error('Workspace preparation was not confirmed.');setPreview(null);setMessage('Workspace ready: '+result.workspace+'. No native session was created.')})}/>}
 {busy&&<p role="status">Waiting for workspace service…</p>}{error&&<p role="alert">{error}</p>}{message&&<p role="status">{message}</p>}</section>
}
