import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {it,expect} from 'vitest';
import {adapt} from './adapter';
import {TeamView} from './TeamView';
const snapshot={local:{sessions:[]},team:{availability:{tasks:true,control:true},tasks:{tasks:[{id:'retired-task',title:'Retired work must stay terminal',status:'retired',owner:'alpha'}]},control:{agents:[{id:'alpha'}]}}};
it('keeps retired work terminal in the board and team summaries',()=>{
 expect(adapt(snapshot).issues[0]).toMatchObject({status:'cancelled',rawStatus:'retired'});
 const html=renderToStaticMarkup(React.createElement(TeamView,{snapshot,onAgentTasks:()=>{},onTask:()=>{}}));
 expect(html).toContain('No open tasks assigned.');
 expect(html).not.toContain('Retired work must stay terminal');
});
