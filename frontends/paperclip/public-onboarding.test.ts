import {describe,it,expect} from 'vitest';
import {nameError, onboardingRequest, sameTarget, collectSessions} from './public-onboarding';
describe('public onboarding boundaries',()=>{
 it('validates syntax locally and leaves Unicode uniqueness to the server',()=>{expect(nameError('',[])).toBeTruthy();expect(nameError(' Sage',[])).toBeTruthy();expect(nameError('Ａrvi',[{name:'Sage'}])).toBe('');expect(nameError('New',[])).toBe('')});
 it('does not turn missing API into success',async()=>{await expect(onboardingRequest('x','',undefined,async()=>new Response('',{status:404}))).rejects.toThrow('unavailable')});
 it('keeps connection incarnation exact',()=>{expect(sameTarget({machine_id:'m',agent_id:'a',workspace_id:'w',connection_id:'1'},{machine_id:'m',agent_id:'a',workspace_id:'w',connection_id:'2'})).toBe(false)});
 it('collects every all-session page',async()=>{let calls=0;const target={machine_id:'m',agent_id:'a',workspace_id:'w',connection_id:'c'};const items=await collectSessions(target,async(cursor)=>{calls++;return {items:[{route:{target,session_id:cursor?'2':'1'},title:'Session',updated_at:1}],total:2,next_cursor:cursor?null:'next'}});expect(items).toHaveLength(2);expect(calls).toBe(2)});
});
