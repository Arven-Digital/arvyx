import {workspaceRequest} from './workspace-request';
// No background retries: a lost reply can follow a committed AMC write.
export async function createTask(capability:string, title:string, owner:string, idempotencyKey:string, transport:typeof fetch=fetch){
 const base=workspaceRequest(capability);
 const response=await transport('/api/team/action',{
  ...base,method:'POST',
  headers:{...base.headers,'Content-Type':'application/json'},
  body:JSON.stringify({action:'task-create',payload:{title,owner,idempotency_key:idempotencyKey}})
 });
 if(!response.ok)throw Error('AMC refused or delivery is uncertain. Refresh and reconcile before another submission.');
 return response.json();
}
