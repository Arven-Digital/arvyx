import {it,expect} from 'vitest';
import {ReviewedActionFlow} from './ReviewedActions';
it('waits for displayed review and explicit commit, then submits its exact digest once',async()=>{
 const calls:any[]=[];let shown:any;
 const base=async(path:string,body?:unknown)=>{calls.push([path,body]);return path.endsWith('prepare')?{consent_id:'one',sha256:'digest',request:body}:{status:'completed'}};
 const flow=new ReviewedActionFlow(base,review=>shown=review);
 const result=flow.request('/sessions/select',{route:'exact',confirmed:true});
 await Promise.resolve();expect(shown.consent_id).toBe('one');expect(calls).toHaveLength(1);
 await expect(flow.request('/sessions/select',{})).rejects.toThrow('current review');
 await flow.commit();await flow.commit();expect(await result).toEqual({status:'completed'});
 expect(calls[1]).toEqual(['/actions/commit',{consent_id:'one',consent_sha256:'digest',confirmed:true}]);expect(calls).toHaveLength(2);
});
it('cancels without dispatch and invalidates a late preview from the previous identity',async()=>{
 let finish!:(value:unknown)=>void;let shown:any;const calls:string[]=[];
 const flow=new ReviewedActionFlow(async(path)=>{calls.push(path);return new Promise(resolve=>finish=resolve)},review=>shown=review);
 const result=flow.request('/manual/connect',{});const refused=expect(result).rejects.toThrow('identity changed');
 flow.cancel();finish({consent_id:'old',sha256:'old'});await refused;
 await flow.commit();expect(shown).toBeNull();expect(calls).toEqual(['/actions/prepare']);
});
