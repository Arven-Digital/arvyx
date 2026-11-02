import {workspaceRequest} from './workspace-request';
import {validateSnapshot} from './adapter';
// The local launcher uses a fragment, never query parameters. Consume before requests.
export function consumeLocalLaunchCapability(location:Pick<Location,'hostname'|'hash'|'pathname'|'search'>,replace:(data:any,unused:string,url:string)=>void):string{
 if(!['127.0.0.1','localhost','[::1]'].includes(location.hostname)||!/^#[A-Za-z0-9_-]{32,128}$/.test(location.hash))return '';
 const capability=location.hash.slice(1);
 replace(null,'',location.pathname+location.search);
 return capability;
}
export type LocalConnection={mode:'real-local';owner_connected:boolean;native_session_control:boolean;external_delegation:boolean};
export async function getLocalConnection(capability:string,transport:typeof fetch=fetch):Promise<LocalConnection>{
 const response=await transport('/api/local-connection',workspaceRequest(capability));
 if(!response.ok)throw Error('Local real workspace unavailable or unauthorized. No demo fallback.');
 const value=await response.json();
 if(value?.mode!=='real-local'||typeof value.owner_connected!=='boolean'||typeof value.native_session_control!=='boolean'||typeof value.external_delegation!=='boolean')throw Error('Local real workspace unavailable or unauthorized. No demo fallback.');
 return {mode:'real-local',owner_connected:value.owner_connected,native_session_control:value.native_session_control,external_delegation:value.external_delegation};
}
export async function connectLocalWorkspace(capability:string,transport:typeof fetch=fetch):Promise<any>{
 try{
  const connection=await getLocalConnection(capability,transport);
  if(!connection.owner_connected)throw Error();
  const response=await transport('/api/snapshot',workspaceRequest(capability));
  if(!response.ok)throw Error();
  return validateSnapshot(await response.json());
 }catch{throw Error('Local real workspace unavailable or unauthorized. No demo fallback.')}
}
