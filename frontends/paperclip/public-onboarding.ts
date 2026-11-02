import {workspaceRequest} from './workspace-request';
export type Target={machine_id:string;agent_id:string;workspace_id:string;connection_id:string;label?:string};
export type Session={route:{target:Target;session_id:string};title:string;updated_at:number};
export type Page={items:Session[];total:number;next_cursor:string|null};
export function sameTarget(a:Target,b:Target){return !!a&&!!b&&['machine_id','agent_id','workspace_id','connection_id'].every(k=>a[k as keyof Target]===b[k as keyof Target])}
export type OwnerSession={target:Target;owner_session:string;owner_incarnation:string;conversation:string};
export function ownerSessionPage(page:any,target:Target,limit:number):{items:OwnerSession[];next_cursor:string|null}{
 if(!Array.isArray(page?.items)||page.items.length>limit||!(page.next_cursor===null||typeof page.next_cursor==='string'&&/^[1-9][0-9]{0,18}$/.test(page.next_cursor)))throw Error('Invalid owner session page. Reload it.');
 const seen=new Set<string>();
 for(const item of page.items){
  if(!sameTarget(item?.target,target)||!['owner_session','owner_incarnation','conversation'].every(k=>typeof item?.[k]==='string'&&item[k].length>0)||seen.has(item.owner_session))throw Error('Owner session destination mismatch. Reload it.');
  seen.add(item.owner_session);
 }
 return {items:page.items,next_cursor:page.next_cursor};
}
export function nameError(name:string,agents:{name:string}[]){if(!name.trim()||name!==name.trim()||name.length>128||/\p{C}/u.test(name))return 'Enter a name without leading spaces or control characters (up to 128 characters).';return ''}
export async function onboardingRequest(capability:string,path:string,body?:unknown,transport:typeof fetch=fetch):Promise<any>{
 if(!capability)throw Error('Connect to your workspace first.');
 // Translate the UI model to the current public transport; never invent capabilities.
 if(path===''){
  const discovery=await onboardingRequest(capability,'/discover',{},transport);
  const agents=await onboardingRequest(capability,'/agents',undefined,transport);
  const caps=await onboardingRequest(capability,'/capabilities',undefined,transport);
  const targets=await onboardingRequest(capability,'/targets',undefined,transport);
  return {...caps,mode:caps.mode??discovery.mode,candidates:discovery.candidates.map((c:any)=>({...c,available:c.available===true})),agents:agents.items,harnesses:caps.harnesses??[],targets:targets.items??[],owner_host:caps.owner_host,creation_available:caps.creation_available===true&&caps.creation_mode==='clean_metadata_only',creation_reason:'Creates an isolated metadata profile; runtime execution requires a separately approved executor.',environments:caps.environments??[{id:'metadata',available:true}],truncated:discovery.truncated,incomplete:discovery.incomplete,incomplete_reasons:discovery.incomplete_reasons??[]};
 }
 let route=path;
 if((path==='/agents'&&body!==undefined)||path==='/connect'||path==='/sessions/select'){
  if((body as any)?.confirmed!==true)throw Error('Explicit per-action confirmation required.');
 }
 if(path==='/agents'&&body!==undefined){route='/agents/create';body={name:(body as any).name,harness:(body as any).harness,confirmed:(body as any).confirmed};}

 if(path==='/connect')body={candidate_id:(body as any).candidate_id,confirmed:(body as any).confirmed};
 if(path==='/sessions/list'){const b=body as any;route=b.mode==='recent'?'/sessions/recent':'/sessions/all';body=b.mode==='recent'?{target:b.target}:{target:b.target,query:b.query,cursor:b.cursor,limit:100};}
 let response:Response;try{response=await transport('/api/public-onboarding'+route,{...workspaceRequest(capability),...(body===undefined?{}:{method:'POST',headers:{...workspaceRequest(capability).headers,'Content-Type':'application/json'},body:JSON.stringify(body)})})}catch{throw Error(body===undefined?'Service unavailable. Nothing retried.':'Response unavailable; operation outcome is unknown. Reconcile the recorded attempt before another action. Nothing retried.')}
 if(!response.ok){let reason='',uncertain=false,attempt='';try{const failure=await response.json();reason=typeof failure.error==='string'?failure.error.replaceAll('_',' '):'';uncertain=failure.reconcile_required===true;attempt=typeof failure.consent_id==='string'&&/^[0-9a-f]{32}$/.test(failure.consent_id)?failure.consent_id:''}catch{}if(reason==='duplicate agent name')throw Error('This name is already in use. Choose another.');throw Error(`${response.status===400?'Request validation failed':'Service unavailable'} (${response.status})${reason?': '+reason:''}. ${uncertain?'Outcome uncertain; reconcile the recorded attempt'+(attempt?' '+attempt:'')+'.':'No automatic retry.'}`)}
 let data:any;try{data=await response.json()}catch{throw Error('Service unavailable: invalid response.')}
 if(data.available===false)throw Error(typeof data.reason==='string'?data.reason:'This operation is unavailable.');return data;
}
export async function collectSessions(target:Target,load:(cursor:string|null)=>Promise<Page>){const all:Session[]=[];const seen=new Set<string>();const cursors=new Set<string>();let cursor:string|null=null;let total:number|undefined;do{const page=await load(cursor);if(!Array.isArray(page.items)||!Number.isInteger(page.total)||page.total<0||(total!==undefined&&total!==page.total))throw Error('Session list changed. Reload it.');total=page.total;for(const item of page.items){if(!item.route||!sameTarget(item.route.target,target)||seen.has(item.route.session_id))throw Error('Session destination mismatch. Reload it.');seen.add(item.route.session_id);all.push(item)}cursor=page.next_cursor;if(cursor!==null){if(typeof cursor!=='string'||cursors.has(cursor))throw Error('Invalid session cursor.');cursors.add(cursor)}}while(cursor!==null);if(all.length!==total)throw Error('Incomplete session list. Reload it.');return all}
