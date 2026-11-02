import {describe,it,expect,vi} from 'vitest';
import {getLocalConnection,connectLocalWorkspace,consumeLocalLaunchCapability} from './local-workspace';
describe('private local launch handoff',()=>{
 it('consumes an exact loopback capability into memory and clears history before any request',()=>{
  const replace=vi.fn();const token='a'.repeat(43);
  expect(consumeLocalLaunchCapability({hostname:'127.0.0.1',hash:'#'+token,pathname:'/',search:''},replace)).toBe(token);
  expect(replace).toHaveBeenCalledWith(null,'','/');
 });
 it('never interprets demo/task routes or non-loopback locations as credentials',()=>{
  const replace=vi.fn();
  for(const hash of ['#preview=synthetic','#task=abc','#short'])expect(consumeLocalLaunchCapability({hostname:'localhost',hash,pathname:'/',search:''},replace)).toBe('');
  expect(consumeLocalLaunchCapability({hostname:'example.com',hash:'#'+'a'.repeat(43),pathname:'/',search:''},replace)).toBe('');
  expect(replace).not.toHaveBeenCalled();
 });
});
const config={mode:'real-local',owner_connected:true,native_session_control:false,external_delegation:false};
describe('explicit local-real connection',()=>{
 it('reads only sanitized authenticated connection metadata',async()=>{
  const transport=vi.fn().mockResolvedValue({ok:true,json:async()=>({...config,secret:'not forwarded'})});
  expect(await getLocalConnection('memory-only',transport)).toEqual(config);
  expect(transport).toHaveBeenCalledExactlyOnceWith('/api/local-connection',{headers:{Authorization:'Bearer memory-only'},credentials:'omit',cache:'no-store',redirect:'error'});
 });
 it('does not infer real connectivity from missing, malformed or synthetic configuration',async()=>{
  for(const value of [null,{}, {...config,mode:'synthetic'}, {...config,owner_connected:'true'}]){
   await expect(getLocalConnection('memory-only',vi.fn().mockResolvedValue({ok:true,json:async()=>value}))).rejects.toThrow();
  }
 });
 it('reads snapshot only after verified local mode and never POSTs or starts sessions',async()=>{
  const transport=vi.fn().mockResolvedValueOnce({ok:true,json:async()=>config}).mockResolvedValueOnce({ok:true,json:async()=>({team:{availability:{}},local:{}})});
  expect(await connectLocalWorkspace('memory-only',transport)).toEqual({team:{availability:{}},local:{}});
  expect(transport.mock.calls.map(c=>c[0])).toEqual(['/api/local-connection','/api/snapshot']);
  expect(transport.mock.calls.every(c=>!c[1]?.method)).toBe(true);
 });
 it('fails closed without echoing backend secrets or falling back to demo',async()=>{
  for(const transport of [vi.fn().mockRejectedValue(Error('private credential')),vi.fn().mockResolvedValue({ok:true,json:async()=>({...config,owner_connected:false})})]){
   await expect(connectLocalWorkspace('memory-only',transport)).rejects.toThrow('Local real workspace unavailable or unauthorized. No demo fallback.');
   expect(transport).toHaveBeenCalledTimes(1);
  }
 });
});
