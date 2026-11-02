import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {AgentIdentity} from './LocalIdentity';
describe('local agent identity',()=>{
 it('renders initials and the name with no image request',()=>{
  const html=renderToStaticMarkup(React.createElement(AgentIdentity,{agent:{id:'local-1',name:'Claude Researcher'},size:'sm'}));
  expect(html).toContain('>CR<');expect(html).toContain('Claude Researcher');
  expect(html).not.toContain('<img');expect(html).not.toContain('/api/agent-avatars');
  expect(renderToStaticMarkup(React.createElement(AgentIdentity,{agent:{id:'x'}}))).toContain('>AG<');
 });
 it('replaces the vendored identity in every local view without touching vendored bytes',()=>{
  for(const file of ['PublicOnboarding.tsx','TeamView.tsx','main.tsx']){
   const source=readFileSync(new URL('./'+file,import.meta.url),'utf8');
   expect(source).toContain("import {AgentIdentity} from './LocalIdentity'");
   expect(source).not.toContain('./vendor/components/AgentIdentity');
  }
  const vendored=readFileSync(new URL('./vendor/components/AgentAvatar.tsx',import.meta.url),'utf8');
  expect(vendored).toContain('agentAvatarUrl(identity, size, 1, pose, muted)');
 });
});
