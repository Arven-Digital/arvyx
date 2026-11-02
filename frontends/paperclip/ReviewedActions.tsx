import React,{useEffect,useRef,useState} from 'react';
import {Button} from './vendor/components/ui/button';
const protectedActions=new Set(['/native/revoke','/native/present','/native/attach','/native/open','/connect','/profiles/connect','/profiles/register','/manual/connect','/sessions/select','/instructions/preview','/pairing/issue','/pairing/decide']);
type Request=(path:string,body?:unknown)=>Promise<any>;
export class ReviewedActionFlow {
 private pending:{resolve:(result:any)=>void;reject:(error:Error)=>void}|null=null;
 private review:any=null;
 private active=false;
 private generation=0;
 constructor(public base:Request,private publish:(review:any)=>void){}
 async request(path:string,body?:unknown):Promise<any>{
  if(!protectedActions.has(path))return this.base(path,body);
  if(this.active)throw Error('Finish the current review first.');
  this.active=true;const generation=this.generation;
  try{
   const prepared=await this.base('/actions/prepare',{action:path.slice(1),request:body});
   if(generation!==this.generation)throw Error('Setup identity changed; review cancelled.');
   this.review=prepared;
   return await new Promise<any>((resolve,reject)=>{this.pending={resolve,reject};this.publish(prepared)});
  }finally{if(generation===this.generation)this.active=false}
 }
 async commit(){
  const pending=this.pending,review=this.review;
  if(!pending||!review)return;
  this.pending=null;this.review=null;this.publish(null);
  try{pending.resolve(await this.base('/actions/commit',{consent_id:review.consent_id,consent_sha256:review.sha256,confirmed:true}))}
  catch(error){pending.reject(error instanceof Error?error:Error('Outcome uncertain; inspect the recorded attempt.'))}
 }
 cancel(){this.generation++;this.pending?.reject(Error('Review cancelled.'));this.pending=null;this.review=null;this.active=false;this.publish(null)}
}
export function useReviewedActions(base:Request,enabled:boolean,identity:string){
 const [review,setReview]=useState<any>(null),[committing,setCommitting]=useState(false);
 const flow=useRef<ReviewedActionFlow|null>(null);
 if(flow.current===null)flow.current=new ReviewedActionFlow(base,setReview);
 flow.current.base=base;
 useEffect(()=>()=>{flow.current?.cancel()},[identity]);
 const request=(path:string,body?:unknown)=>enabled?flow.current!.request(path,body):base(path,body);
 const reviewDialog=review&&<section role="dialog" aria-modal="true" aria-label="Confirm reviewed action"><h3>Review this exact action</h3><p>{review.action}</p><pre>{JSON.stringify(review.request,null,2)}</pre><p>Expires: {new Date(review.expires_at*1000).toLocaleString()}</p><Button disabled={committing} onClick={async()=>{setCommitting(true);try{await flow.current!.commit()}finally{setCommitting(false)}}}>Confirm this exact action</Button><Button disabled={committing} onClick={()=>flow.current!.cancel()}>Cancel</Button></section>;
 return {request,reviewDialog};
}
