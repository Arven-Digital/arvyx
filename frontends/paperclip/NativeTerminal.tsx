import {nativeAttachmentIdentity,NativeSessionClient} from './native-session';
import React,{useState,useMemo,useEffect,useRef} from 'react';
import type {Target} from './public-onboarding';
type Props={opened:any;target:Target;request:(path:string,body?:unknown)=>Promise<any>;onClose:()=>void};
export function NativeTerminal(props:Props){
 return <AttachmentTerminal key={nativeAttachmentIdentity(props.opened,props.target)} {...props}/>;
}
function AttachmentTerminal({opened,target,request,onClose}:Props){
 const [output,setOutput]=useState(''),[cursor,setCursor]=useState(0),[text,setText]=useState(''),[draft,setDraft]=useState<any>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[notice,setNotice]=useState('');
 const identity=nativeAttachmentIdentity(opened,target);
 const client=useMemo(()=>new NativeSessionClient(opened,target,request),[identity]);
 const active=useRef(true),pending=useRef(false);
 const decoder=useRef(new TextDecoder());
 useEffect(()=>{active.current=true;return()=>{active.current=false;client.invalidate()}},[client]);
 async function call(operation:string,fields:unknown){return client.call(operation,fields)}
 async function run(action:()=>Promise<void>){if(pending.current||!active.current)return;pending.current=true;setBusy(true);setError('');try{await action()}catch(e){if(active.current)setError(e instanceof Error?e.message:'Attachment unavailable. Nothing retried.')}finally{pending.current=false;if(active.current)setBusy(false)}}
 async function readOutput(){
  const page=await call('read',{cursor});
  if(!active.current)return;
  if(page.truncated)decoder.current=new TextDecoder();
  const bytes=Uint8Array.from(atob(page.data),(c:string)=>c.charCodeAt(0));
  const value=decoder.current.decode(bytes,{stream:true}).replace(/[\x00-\x08\x0b-\x1f\x7f]/g,'');
  setOutput(old=>((page.truncated?'[Output gap: earlier bytes are unavailable.]\n':old)+value).slice(-65536));
  setCursor(page.cursor);
 }
 return <section aria-label="Exact native session"><h4>Native conversation {opened.conversation}</h4><p>Attached to owner session {opened.owner_session}. Output is plain text; use the native terminal for interactive screen applications.</p><button disabled={busy} onClick={()=>run(readOutput)}>Read latest output</button><pre>{output}</pre><label>Message or shell input<textarea disabled={busy} value={text} onChange={e=>{setText(e.target.value);setDraft(null)}}/></label><button disabled={busy||!text.trim()} onClick={()=>run(async()=>setDraft(await client.stage(text)))}>Review input</button>{draft&&<section aria-label="Confirm exact input"><pre>{draft.text}</pre><button disabled={busy} onClick={()=>run(async()=>{setDraft(null);const result=await client.send();setText('');setNotice(result.accepted?'Input accepted by the owner; delivery is not confirmed.':'Input refused. Reconcile before another attempt.')})}>Send this exact reviewed input</button><button disabled={busy} onClick={()=>{client.cancelReview();setDraft(null)}}>Cancel</button></section>}<button disabled={busy} onClick={()=>run(async()=>{await client.detach();if(active.current)onClose()})}>Detach</button>{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</section>
}
