import React,{useState} from 'react';
import {createTask} from './actions';
export function TaskComposer({capability,available,onCreated}:{capability:string,available:boolean,onCreated:()=>Promise<void>}){
 const [title,setTitle]=useState('');const [owner,setOwner]=useState('');
 const [pending,setPending]=useState(false);const [uncertain,setUncertain]=useState(false);
 const [message,setMessage]=useState('');
 async function submit(e:React.FormEvent){
  e.preventDefault();if(pending||uncertain||!available)return;
  setPending(true);setMessage('');
  try{
   await createTask(capability,title,owner,crypto.randomUUID());
   setTitle('');setOwner('');setMessage('AMC accepted the task. Refreshing authority…');
   await onCreated();
   setMessage('Task accepted by AMC. Check the current authority snapshot.');
  }catch{
   setUncertain(true);setMessage('Submission refused or outcome uncertain. Draft retained. Read the authority and reconcile before creating another task.');
  }finally{setPending(false)}
 }
 return <section aria-label="Create task"><details><summary>New task</summary><form onSubmit={submit}>
 <label>Title <input required maxLength={1000} value={title} onChange={e=>setTitle(e.target.value)}/></label>
 <label>Owner <input required maxLength={128} value={owner} onChange={e=>setOwner(e.target.value)}/></label>
 <button disabled={!available||pending||uncertain}>{pending?'Submitting…':'Create AMC task'}</button>
 {uncertain&&<button type="button" disabled={pending} onClick={async()=>{setPending(true);try{await onCreated();setMessage('Check the refreshed task list. No action was resent.')}finally{setPending(false)}}}>Refresh authority (no resend)</button>}
 <output aria-live="polite">{message}</output>
 {!available&&<p>Task authority unavailable. No writes are queued.</p>}
 </form></details></section>;
}
