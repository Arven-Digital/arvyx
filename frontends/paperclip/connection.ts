// fixtureOnly must come from operator-controlled fixture configuration, never a URL.
export function demoConnectionAllowed(fixtureOnly:boolean,syntheticPreview:boolean,hostname:string){
 return fixtureOnly===true&&syntheticPreview===true&&['127.0.0.1','localhost','[::1]'].includes(hostname);
}
import {workspaceRequest} from './workspace-request';
import {validateSnapshot} from './adapter';
export {SYNTHETIC_DEMO_CAPABILITY} from './workspace-request';
export async function connectSnapshot(capability:string,transport:typeof fetch=fetch):Promise<any>{
 if(!capability.trim()||/[\r\n]/.test(capability))throw Error('Enter an access credential supplied by your local operator.');
 try{
  const response=await transport('/api/snapshot',workspaceRequest(capability));
  if(!response.ok)throw Error();
  return validateSnapshot(await response.json());
 }catch{
  throw Error('Connection unavailable. Check access with your local operator. No actions queued.');
 }
}
