import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {LocalOnboardingControls} from './LocalOnboardingControls';
const base={request:async()=>({}),onRefresh:async()=>{},pairing:false,busy:false,perform:()=>{}};
describe('manual metadata connection',()=>{
 it('lists the server-advertised adapters and selects the first by default',()=>{
  const html=renderToStaticMarkup(React.createElement(LocalOnboardingControls,{...base,adapters:[{id:'hermes',label:'Hermes'},{id:'claude',label:'Claude Code'},{id:'codex',label:'Codex'}]}));
  expect(html).toContain('<option value="hermes"');expect(html).toContain('<option value="claude">Claude Code</option>');expect(html).toContain('<option value="codex">Codex</option>');
  expect(html).toMatch(/<option[^>]*selected[^>]*>Hermes<\/option>/);
  expect(html).not.toMatch(/<option[^>]*selected[^>]*>(Claude Code|Codex)<\/option>/);
  expect(html).toContain('read-only session metadata');expect(html).not.toContain('registered Hermes agent ID');
 });
 it('falls back to Hermes alone when the server lists no adapters',()=>{
  for(const adapters of [undefined,[],[{id:'',label:'x'}]] as any[]){
   const html=renderToStaticMarkup(React.createElement(LocalOnboardingControls,{...base,adapters}));
   expect(html).toContain('<option value="hermes"');expect(html).not.toContain('value="claude"');
  }
 });
 it('sends the chosen family, never a hard-coded one',()=>{
  const source=readFileSync(new URL('./LocalOnboardingControls.tsx',import.meta.url),'utf8');
  expect(source).toMatch(/request\('\/manual\/connect',\{family:selected,path,agent_id:agent,confirmed:true\}\)/);
  expect(source).not.toContain("family:'hermes'");
  const parent=readFileSync(new URL('./PublicOnboarding.tsx',import.meta.url),'utf8');
  expect(parent).toContain('adapters={catalog.metadata_adapters}');
 });
});
