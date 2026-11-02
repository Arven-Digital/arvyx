import {describe,it,expect,vi} from 'vitest';
import {NativeSessionClient} from './native-session';
const target={machine_id:'m',agent_id:'a',workspace_id:'w',connection_id:'c'};
const opened={target,owner_session:'sid',owner_incarnation:'boot',attachment:{attachment:'lease'}};
describe('exact live native attachment',()=>{
 it('does nothing on construction and never retries a lost input acknowledgement',async()=>{
  const request=vi.fn().mockResolvedValueOnce({id:'draft',session:'sid',text:'hello',sha256:'digest'}).mockRejectedValueOnce(Error('lost acknowledgement'));
  const client=new NativeSessionClient(opened,target,request);expect(request).not.toHaveBeenCalled();
  await expect(client.send()).rejects.toThrow('Fresh exact');await client.stage('hello');await expect(client.send()).rejects.toThrow('lost acknowledgement');await expect(client.send()).rejects.toThrow('Fresh exact');
  expect(request).toHaveBeenCalledTimes(2);expect(request.mock.calls[1][1]).toMatchObject({attachment:'lease',operation:'send',fields:{draft_id:'draft',sha256:'digest'}});
 });
 it('refuses destination changes and clears a lease after detach even if its acknowledgement is lost',async()=>{
  expect(()=>new NativeSessionClient(opened,{...target,connection_id:'other'},vi.fn())).toThrow();
  const request=vi.fn().mockRejectedValue(Error('lost detach'));const client=new NativeSessionClient(opened,target,request);
  await expect(client.detach()).rejects.toThrow();await expect(client.call('read',{cursor:0})).rejects.toThrow('closed');expect(request).toHaveBeenCalledTimes(1);
 });
});
