import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,it,expect} from 'vitest';
import {TeamView} from './TeamView';
const snapshot={team:{availability:{control:true,tasks:true,approvals:false,handoffs:true,threads:true},control:{agents:[{id:'nova',display_name:'Nova',status:'active',machine:'workstation'}]},tasks:{tasks:[{id:'t_one',title:'Build cockpit',owner:'nova',status:'active'},{id:'t_two',title:'Needs owner',status:'pending'}]}},local:{sessions:[]}};
const render=(s:any)=>renderToStaticMarkup(React.createElement(TeamView,{snapshot:s,onAgentTasks:()=>{},onTask:()=>{}}));
describe('Team view',()=>{
 it('sol32 renders returned counts and unknown membership for the 101st agent in a truncated registry',()=>{
  const agents=Array.from({length:100},(_,i)=>({id:`agent${i}`,status:'idle'}));
  const html=render({team:{availability:{control:true,tasks:true},control:{agents,source:{bounds:{agents_discovered:101,agents_returned:100,agents_invalid:0,agents_truncated:true}}},tasks:{tasks:[{id:'omitted',title:'Owned by omitted agent',owner:'agent100',status:'active'}]}}});
  expect(html).toContain('Returned agents');expect(html).toContain('100');expect(html).toContain('101 discovered');expect(html).toContain('Registry membership incomplete');expect(html).toContain('Owner membership unknown: agent100');expect(html).not.toContain('Work without a registered owner');expect(html).not.toContain('All open tasks have a registered owner');
 });
 it('sol32 labels projected idle as coordination workload, never registry or heartbeat state',()=>{
  const html=render({...snapshot,team:{...snapshot.team,control:{agents:[{id:'offline-in-registry',status:'idle'}]}}});
  expect(html).toContain('Coordination workload: idle');expect(html).toContain('not registry status or heartbeat reachability');expect(html).not.toContain('Statuses below are registry values');
 });
 it.each([{agents_invalid:1,agents_truncated:false,agents_discovered:2,agents_returned:1},undefined])('sol32 does not infer membership from invalid or absent completeness metadata',bounds=>{
  const html=render({...snapshot,team:{...snapshot.team,control:{...snapshot.team.control,source:{bounds}},tasks:{tasks:[{id:'missing',title:'Unknown owner',owner:'omitted',status:'active'}]}}});expect(html).toContain('Owner membership unknown: omitted');expect(html).not.toContain('Work without a registered owner');
 });
 it('sol32 permits negative membership only for explicitly complete registry results',()=>{
  const html=render({...snapshot,team:{...snapshot.team,control:{...snapshot.team.control,source:{bounds:{agents_discovered:1,agents_returned:1,agents_invalid:0,agents_truncated:false}}},tasks:{tasks:[{id:'missing',title:'Absent owner',owner:'omitted',status:'active'}]}}});expect(html).toContain('Work without a registered owner');expect(html).toContain('Owner outside returned registry: omitted');
 });
 it('sol22 keeps ownership unknown when tasks succeed but the registry fails',()=>{const html=render({...snapshot,team:{...snapshot.team,availability:{control:false,tasks:true}}});expect(html).toContain('Ownership unknown');expect(html).not.toContain('Work without a registered owner');expect(html).not.toContain('Owner outside returned registry');expect(html).not.toContain('All open tasks have a registered owner');});
 it('renders real Paperclip identities/cards and useful task summaries without JSON',()=>{const html=render(snapshot);expect(html).toContain('data-slot="card"');expect(html).toContain('Nova');expect(html).toContain('Build cockpit');expect(html).toContain('Needs owner');expect(html).toContain('Unassigned');expect(html).toContain('workstation');expect(html).not.toContain('<pre');expect(html).toContain('not live reachability');});
 it('does not present unavailable authority data as current or empty',()=>{const html=render({...snapshot,team:{...snapshot.team,availability:{control:false,tasks:false}}});expect(html).toContain('Registry unavailable');expect(html).toContain('Task authority unavailable');expect(html).not.toContain('Build cockpit');expect(html).not.toContain('Nova');});
 it('distinguishes confirmed empty collections',()=>{const html=render({team:{availability:{control:true,tasks:true},control:{agents:[]},tasks:{tasks:[]}},local:{sessions:[]}});expect(html).toContain('No registered agents returned');expect(html).toContain('No tasks returned');});
 it('escapes authority text and preserves exact raw lifecycle statuses',()=>{const html=render({...snapshot,team:{...snapshot.team,tasks:{tasks:[{id:'x',title:'<script>bad</script>',owner:'missing',status:'awaiting_custom_review'}]}}});expect(html).not.toContain('<script>');expect(html).toContain('&lt;script&gt;');expect(html).toContain('awaiting_custom_review');expect(html).toContain('missing');});
});
