import {describe,it,expect} from 'vitest';
import {adapt} from './adapter';
import {applyIssueFilters,defaultIssueFilterState} from './vendor/lib/issue-filters';
describe('AMC authority adapter',()=>{
 const snapshot={local:{tasks:[{id:'local',title:'local',status:'open'}],sessions:[{task:'t1',project:'p1'}]},team:{availability:{tasks:true},tasks:{tasks:[{id:'t1',title:'Real task',status:'open',owner:'a1'},{id:'t2',title:'Blocked task',status:'blocked',owner:'a2'}]}}};
 it('uses permission-checked task authority and preserves exact IDs/status',()=>{const m=adapt(snapshot);expect(m.issues.map(t=>t.id)).toEqual(['t1','t2']);expect(m.issues[0].rawStatus).toBe('open');expect(m.issues[0].status).toBe('todo')});
 it('uses upstream filtering for exact owner and project',()=>{const m=adapt(snapshot);expect(applyIssueFilters(m.issues,{...defaultIssueFilterState,assignees:['a1'],projects:['p1']})).toHaveLength(1)});
 it('does not disguise unauthorized team data as current data',()=>{const m=adapt({...snapshot,team:{availability:{tasks:false}}});expect(m.issues[0].id).toBe('local')});
 it('maps retired work to a closed lane without changing raw status',()=>{const m=adapt({local:{tasks:[{id:'r',title:'Retired task',status:'retired'}]},team:{availability:{tasks:false}}});expect(m.issues[0].status).toBe('cancelled');expect(m.issues[0].rawStatus).toBe('retired')});
 it('preserves unknown status for detail display',()=>{const m=adapt({local:{tasks:[{id:'x',title:'Custom task',status:'custom-status'}]},team:{availability:{tasks:false}}});expect(m.issues[0].rawStatus).toBe('custom-status');expect(m.issues[0].status).toBe('backlog')});
});
