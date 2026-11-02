import {describe,it,expect} from 'vitest';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {WorkspaceReview,SessionPreparation} from './SessionPreparation';
describe('New workspace preparation',()=>{
 it('states the exact effect and requires a separate confirmation',()=>{
  const html=renderToStaticMarkup(React.createElement(WorkspaceReview,{workspace:'/approved/research',onConfirm:()=>{throw Error('render must never commit')},onCancel:()=>{}}));
  expect(html).toContain('/approved/research');expect(html).toContain('Prepare this exact workspace');expect(html).toContain('No native session or process will start');
 });
 it('makes no request during render and asks for authorized roots',()=>{
  const html=renderToStaticMarkup(React.createElement(SessionPreparation,{target:{machine_id:'m',agent_id:'a',workspace_id:'w',connection_id:'c'},request:async()=>{throw Error('no request before click')}}));
  expect(html).toContain('Load authorized workspace roots');expect(html).toContain('does not create a native conversation');
 });
});
