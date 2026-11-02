import {describe,it,expect,vi} from 'vitest';
import {connectExternalAuthority} from './external-http';
describe('explicit external HTTP authority',()=>{
 it('uses explicit same-origin fixture cookie without exposing a bearer',async()=>{vi.stubGlobal('location',new URL('http://127.0.0.1:40305/'));const fetcher=vi.fn(async(_url:any,_init:any)=>new Response(JSON.stringify({issuer:'fixture-issuer',can_export:true,ttl_hours:24,recipients:[],resources:[],fixture_only:true})));const {connectFixtureAuthority}=await import('./external-http');const c=await connectFixtureAuthority(fetcher);expect(c.config.principal).toBe('fixture-issuer');expect(fetcher.mock.calls[0][1]).toMatchObject({credentials:'same-origin',redirect:'error'});expect(fetcher.mock.calls[0][1].headers).not.toHaveProperty('Authorization');vi.unstubAllGlobals()});
 it('rejects unsafe origins before sending credentials',async()=>{const fetcher=vi.fn();await expect(connectExternalAuthority('http://evil.test','secret',fetcher)).rejects.toThrow();expect(fetcher).not.toHaveBeenCalled()});
 it('authenticates config and reads mutations back',async()=>{const calls:any[]=[];const expiresAt=new Date(Date.now()+4*3600000).toISOString();const record={id:'g1',issuer:'issuer',recipient:'cloud',resources:['task:t1'],operations:['read'],created_at:1700000000,expires_at:expiresAt,state:'active'};const fetcher=vi.fn(async(url:any,init:any)=>{calls.push([url,init]);return new Response(JSON.stringify(url.endsWith('/config')?{principal:'issuer',role:'issuer',can_export:true,operations:['read','list'],recipients:[{id:'cloud',label:'Cloud',location:'cloud'}],resources:[{kind:'task',id:'t1'}],expiry_hours:24}:init.method==='POST'?{id:'g1',expires_at:expiresAt}:record))});const connection=await connectExternalAuthority('http://127.0.0.1:1234','fixture',fetcher);const result=await connection.adapter.issue({recipientId:'cloud',kind:'task',resource:'t1',operations:['read'],expiresAt,exclusions:[]});expect(result.id).toBe('g1');expect(JSON.parse(calls[1][1].body).expires_at).toBe(expiresAt);expect(result.expiresAt).toBe(expiresAt);expect(JSON.parse(calls[1][1].body).operations).toEqual(['read']);expect(result.operations).toEqual(['read']);expect(calls.map(c=>c[0])).toEqual(['http://127.0.0.1:1234/external/config','http://127.0.0.1:1234/external/grants','http://127.0.0.1:1234/external/grants/g1']);expect(calls.every(c=>c[1].redirect==='error'&&c[1].credentials==='omit')).toBe(true)});
 it('does not claim success on authorization failure',async()=>{await expect(connectExternalAuthority('http://localhost:1234','bad',async()=>new Response('{}',{status:403}))).rejects.toThrow('403')});
});
it('shares each registered document kind with its exact reviewed manifest',async()=>{
 for(const kind of ['prompt','skill','artifact'] as const){
  const manifest={coverage:'selection',complete:true,files:[{path:kind==='skill'?'SKILL.md':'selected.txt',size_bytes:12,sha256:'a'.repeat(64)}],excluded:[]};
  let issued:any;
  const expiresAt=new Date(Date.now()+4*3600000).toISOString();const record={id:'g1',issuer:'issuer',recipient:'cloud',resources:[`${kind}:selected`],operations:['read'],created_at:1700000000,expires_at:expiresAt,state:'active'};
  const fetcher=async(url:any,init:any)=>{if(init.method==='POST')issued=JSON.parse(init.body);return new Response(JSON.stringify(url.endsWith('/config')?{issuer:'issuer',can_export:true,operations:['read','list'],recipients:[{id:'cloud',label:'Cloud',location:'cloud'}],resources:[{kind,id:'selected',manifest}],ttl_hours:24}:init.method==='POST'?{id:'g1'}:record))};
  const connection=await connectExternalAuthority('http://127.0.0.1:1234','fixture',fetcher);
  const result=await connection.adapter.issue({recipientId:'cloud',kind,resource:'selected',operations:['read'],expiresAt,exclusions:[]});
  expect(result.kind).toBe(kind);expect(issued.operations).toEqual(['read']);expect(result.operations).toEqual(['read']);expect(issued.reviewed_manifests).toEqual({[`${kind}:selected`]:manifest});
 }
});
describe('scoped audit metadata adapter (authored; NOT_EXECUTED)',()=>{
 const config={principal:'issuer',role:'issuer',can_export:true,recipients:[],resources:[],operations:['read'],expiry_hours:24};
 const item={sequence:1,timestamp:'2026-10-29T00:00:00+00:00',event:'access',details:{grant_id:'g1',principal:'recipient',allowed:true}};
 const page={grant_id:'g1',coverage:'scope-indexed-events-only',items:[item],has_more:false,next_cursor:null};
 it('uses an explicit grant route, query escaping and existing credential separation',async()=>{
  const calls:{url:string;init:RequestInit|undefined}[]=[];
  const fetcher:typeof fetch=async(input,init)=>{const url=String(input);calls.push({url,init});return new Response(JSON.stringify(url.endsWith('/config')?config:page))};
  const connection=await connectExternalAuthority('http://127.0.0.1:1234','synthetic',fetcher);
  const result=await connection.adapter.audit!('g1','cursor+/=');
  expect(result.grant_id).toBe('g1');
  const request=new URL(calls[1].url);expect(request.pathname).toBe('/external/grants/g1/audit');expect(request.searchParams.get('cursor')).toBe('cursor+/=');expect(request.searchParams.get('limit')).toBe('50');
  expect(calls[1].init).toMatchObject({method:'GET',credentials:'omit',redirect:'error',cache:'no-store'});
 });
 it('rejects wrong scope, private fields, nonterminating shape and reordered pages',async()=>{
  for(const invalid of [{...page,grant_id:'other'},{...page,items:[{...item,details:{grant_id:'other'}}]},
   {...page,items:[{...item,details:{...item.details,private_reasoning:'not metadata'}}]},
   {...page,has_more:true},{...page,items:[],has_more:true,next_cursor:'cursor'},
   {...page,items:[item,item]}]){
   const fetcher:typeof fetch=async input=>new Response(JSON.stringify(String(input).endsWith('/config')?config:invalid));
   const connection=await connectExternalAuthority('http://127.0.0.1:1234','synthetic',fetcher);
   await expect(connection.adapter.audit!('g1')).rejects.toThrow();
  }
 });
});
