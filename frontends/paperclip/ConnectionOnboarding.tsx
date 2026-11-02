import React,{useEffect,useRef,useState} from 'react';
import {Button} from './vendor/components/ui/button';
import {Card,CardHeader,CardTitle,CardDescription,CardContent} from './vendor/components/ui/card';
import {connectSnapshot,demoConnectionAllowed,SYNTHETIC_DEMO_CAPABILITY} from './connection';
import {connectLocalWorkspace} from './local-workspace';
export type WorkspaceMode='workspace'|'synthetic'|'real-local';
type Props={
 /** Trusted fixture configuration only. Never derive this from route/query/localStorage. */
 fixtureOnly?:boolean;syntheticPreview:boolean;hostname:string;connected:boolean;
 initialCredential?:string;connectionMode?:WorkspaceMode;onConnected:(snapshot:any,capability:string,mode:WorkspaceMode)=>void;onDisconnect:()=>void;
 connectionGeneration?:{current:number};
};
export function ConnectionOnboarding({fixtureOnly=false,syntheticPreview,hostname,connected,initialCredential='',connectionMode,onConnected,onDisconnect,connectionGeneration}:Props){
 const [credential,setCredential]=useState(initialCredential);const [pending,setPending]=useState(false);const [error,setError]=useState('');
 const inFlight=useRef(false);
 const localGeneration=useRef(0);const generation=connectionGeneration??localGeneration;
 useEffect(()=>()=>{generation.current++},[generation]);
 const demo=demoConnectionAllowed(fixtureOnly,syntheticPreview,hostname);
 async function connect(capability:string,mode:WorkspaceMode='workspace'){
  if(inFlight.current)return;inFlight.current=true;setPending(true);setError('');
  const started=++generation.current;
  try{const snapshot=await (mode==='real-local'?connectLocalWorkspace(capability):connectSnapshot(capability));if(started!==generation.current)return;setCredential('');onConnected(snapshot,capability,mode)}
  catch(e){if(started===generation.current){setCredential('');setError(e instanceof Error?e.message:'Connection unavailable. No actions queued.')}}
  finally{inFlight.current=false;if(started===generation.current)setPending(false)}
 }
 if(connected)return <div aria-label="Connection" className="flex items-center gap-3"><span role="status">{connectionMode==='real-local'?'Local real workspace connected':demo?'Test demo connected':'Workspace connected'}</span><Button variant="outline" type="button" onClick={()=>{generation.current++;setPending(false);setCredential('');setError('');onDisconnect()}}>Disconnect</Button></div>;
 return <Card aria-label="Connect workspace" className="my-4 max-w-xl">
  <CardHeader><CardTitle>{demo?'Explore the test demo':'Connect your workspace'}</CardTitle><CardDescription>{demo?'Sample tasks and agents, not live activity.':'Use your workspace access credential. Ask your operator if you need access.'}</CardDescription></CardHeader>
  <CardContent className="space-y-4">
   {demo?<><p>Explore sample work without connecting a live account.</p><Button type="button" disabled={pending} onClick={()=>connect(SYNTHETIC_DEMO_CAPABILITY,'synthetic')}>{pending?'Connecting…':'Open test demo'}</Button></>:<details open={initialCredential?true:undefined}><summary>Connect your workspace</summary><form className="space-y-3" onSubmit={e=>{e.preventDefault();void connect(credential,'real-local')}}>
    <label className="block">Access credential<input className="block w-full rounded-md border p-2" aria-label="Access credential" type="password" autoComplete="off" spellCheck={false} value={credential} disabled={pending} onChange={e=>setCredential(e.target.value)}/></label>
    <p>Connect this presentation to its explicitly configured existing local owner. Existing native sessions are not started or restarted. Use the local presentation credential supplied by your operator, not a provider credential.</p>
    <Button type="submit" disabled={pending||!credential.trim()}>{pending?'Connecting…':'Connect local real workspace'}</Button>
    <details><summary>Other workspace connection</summary><p>Use only when your operator configured the standard workspace snapshot endpoint.</p><Button type="button" disabled={pending||!credential.trim()} onClick={()=>connect(credential)}>Connect workspace</Button></details>
   </form></details>}
   <p className="text-sm text-muted-foreground">Credentials stay in memory for this connection only. Nothing is saved in this browser. Connecting reads a snapshot; it never queues actions.</p>
   {error&&<p role="alert">{error}</p>}
  </CardContent>
 </Card>;
}
