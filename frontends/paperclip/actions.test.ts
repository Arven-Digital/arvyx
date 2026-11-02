import {describe,it,expect,vi} from 'vitest';
import {createTask} from './actions';
describe('governed task submission',()=>{
 it('sends exact authority envelope with explicit capability and idempotency',async()=>{
  const transport=vi.fn().mockResolvedValue({ok:true,json:async()=>({id:'fixture-task'})});
  expect(await createTask('fixture-only','Title','owner','stable-key',transport)).toEqual({id:'fixture-task'});
  const [url,options]=transport.mock.calls[0];expect(url).toBe('/api/team/action');
  expect(options.credentials).toBe('omit');expect(options.cache).toBe('no-store');
  expect(JSON.parse(options.body)).toEqual({action:'task-create',payload:{title:'Title',owner:'owner',idempotency_key:'stable-key'}});
 });
 it('does not retry an uncertain delivery',async()=>{
  const transport=vi.fn().mockRejectedValue(Error('lost reply'));
  await expect(createTask('fixture-only','Title','owner','stable-key',transport)).rejects.toThrow();
  expect(transport).toHaveBeenCalledTimes(1);
 });
 it('does not reflect private denial details',async()=>{
  const transport=vi.fn().mockResolvedValue({ok:false,json:async()=>({error:'/private/path'})});
  await expect(createTask('fixture-only','Title','owner','stable-key',transport)).rejects.toThrow('Refresh and reconcile');
 });
});
