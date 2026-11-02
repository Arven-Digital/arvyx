import React,{useEffect,useRef,useState} from 'react';
import {Button} from './vendor/components/ui/button';
import type {DelegationAuditPage,ExternalDelegationAdapter} from './external-delegation';

type Snapshot={adapter:ExternalDelegationAdapter;grantId:string;page:DelegationAuditPage};
export function DelegationAudit({adapter,grantId}:{adapter:ExternalDelegationAdapter;grantId:string}){
 const [snapshot,setSnapshot]=useState<Snapshot|null>(null);
 const [status,setStatus]=useState({adapter,grantId,pending:false,message:''});
 const activeStatus=status.adapter===adapter&&status.grantId===grantId;
 const pending=activeStatus&&status.pending;
 const message=activeStatus?status.message:'';
 const current=useRef({adapter,grantId,generation:0,busy:false});
 if(current.current.adapter!==adapter||current.current.grantId!==grantId){
  current.current={adapter,grantId,generation:current.current.generation+1,busy:false};
 }
 useEffect(()=>()=>{current.current.generation++;current.current.busy=false},[]);
 const visible=snapshot?.adapter===adapter&&snapshot.grantId===grantId?snapshot.page:null;
 async function load(more=false){
  if(!adapter.available||!adapter.audit||current.current.busy)return;
  const scope=current.current;const generation=++scope.generation;
  scope.busy=true;setStatus({adapter,grantId,pending:true,message:''});
  try{
   const page=await adapter.audit(grantId,more?visible?.next_cursor??undefined:undefined);
   if(current.current!==scope||scope.generation!==generation)return;
   const previous=more?visible?.items??[]:[];
   if(page.grant_id!==grantId||previous.length&&page.items.length&&page.items[0].sequence<=previous[previous.length-1].sequence)throw Error('Audit snapshot ordering changed.');
   const items=[...previous,...page.items];
   if(items.length>500)throw Error('Panel snapshot limit reached.');
   setSnapshot({adapter,grantId,page:{...page,items}});
   setStatus({adapter,grantId,pending:false,message:'Metadata snapshot loaded. This does not certify complete historical coverage.'});
  }catch{
   if(current.current===scope&&scope.generation===generation){setSnapshot(null);setStatus({adapter,grantId,pending:false,message:'Access history unavailable or no longer authorized. Old snapshot cleared; refresh explicitly.'});}
  }finally{
   if(current.current===scope&&scope.generation===generation)scope.busy=false;
  }
 }
 return <section aria-label={`Access history for grant ${grantId}`}>
  <h4>Access history · {grantId}</h4>
  <Button type="button" variant="outline" disabled={!adapter.available||pending} onClick={()=>void load()}>Refresh metadata snapshot</Button>
  {visible&&<><p>Scope-indexed events only. Older unindexed records are not included. This is not a live progress feed.</p>
   <ol>{visible.items.map(item=><li key={item.sequence}><time dateTime={item.timestamp}>{item.timestamp}</time> · {item.event}<pre>{JSON.stringify(item.details,null,2)}</pre></li>)}</ol>
   {!visible.items.length&&<p>No indexed events in this snapshot. This is not proof of no earlier access.</p>}
   {visible.has_more&&(visible.items.length<500?<Button type="button" variant="outline" disabled={pending} onClick={()=>void load(true)}>Load next metadata page</Button>:<p>Panel limit: 500 events. More events exist; the snapshot is incomplete.</p>)}</>}
  <p role="status" aria-live="polite">{message}</p>
 </section>;
}
