import {sameTarget,type Target} from './public-onboarding';
export function nativeAttachmentIdentity(opened:any,target:Target){
 return JSON.stringify([target.machine_id,target.agent_id,target.workspace_id,target.connection_id,
  opened.owner_session,opened.owner_incarnation,opened.attachment?.attachment]);
}
export class NativeSessionClient {
 private draft:any=null;
 private closed=false;
 constructor(private opened:any,private target:Target,private request:(path:string,body:unknown)=>Promise<any>){
  if(!sameTarget(opened.target,target)||typeof opened.owner_session!=='string'||typeof opened.owner_incarnation!=='string'||typeof opened.attachment?.attachment!=='string')throw Error('Exact native attachment required.');
 }
 cancelReview(){this.draft=null}
 invalidate(){this.closed=true;this.draft=null}
 async call(operation:string,fields:unknown){if(this.closed)throw Error('Attachment closed.');const result=await this.request('/native/io',{target:this.target,proof:this.opened,attachment:this.opened.attachment.attachment,operation,fields});if(this.closed)throw Error('Attachment closed.');return result}
 async stage(text:string){this.draft=null;const row=await this.call('stage',{text});if(row.session!==this.opened.owner_session||row.text!==text||typeof row.id!=='string'||typeof row.sha256!=='string')throw Error('Exact input review mismatch.');this.draft=row;return row}
 async send(){const row=this.draft;this.draft=null;if(!row)throw Error('Fresh exact input review required.');return this.call('send',{draft_id:row.id,sha256:row.sha256})}
 async detach(){try{return await this.call('detach',{})}finally{this.invalidate()}}
}
