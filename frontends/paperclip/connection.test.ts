import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,it,expect,vi} from 'vitest';
import {ConnectionOnboarding} from './ConnectionOnboarding';
import {demoConnectionAllowed,connectSnapshot} from './connection';
describe('connection boundary',()=>{
 it('offers explicit real-local connection separately from ordinary credential connection',()=>{
  const html=renderToStaticMarkup(React.createElement(ConnectionOnboarding,{fixtureOnly:false,syntheticPreview:false,hostname:'127.0.0.1',connected:false,onConnected:()=>{},onDisconnect:()=>{}}));
  expect(html).toContain('Connect local real workspace');expect(html).toContain('Existing native sessions are not started or restarted');
 });
 it('requires explicit fixture configuration, synthetic route and exact loopback',()=>{
  expect(demoConnectionAllowed(true,true,'127.0.0.1')).toBe(true);
  for(const args of [[false,true,'127.0.0.1'],[true,false,'127.0.0.1'],[true,true,'example.com'],[true,true,'127.0.0.1.evil.test']] as const)
   expect(demoConnectionAllowed(...args)).toBe(false);
 });
 it('reads only same-origin snapshot without cookies, persistence or retries',async()=>{
  const snapshot={local:{tasks:[],sessions:[]},team:{availability:{tasks:false,control:false}}};
  const transport=vi.fn().mockResolvedValue({ok:true,json:async()=>snapshot});
  await expect(connectSnapshot('memory-only',transport)).resolves.toEqual(snapshot);
  expect(transport).toHaveBeenCalledExactlyOnceWith('/api/snapshot',{headers:{Authorization:'Bearer memory-only'},credentials:'omit',cache:'no-store',redirect:'error'});
 });
 it('never reflects a server denial or transport secret',async()=>{
  for(const transport of [vi.fn().mockResolvedValue({ok:false}),vi.fn().mockRejectedValue(Error('private-secret'))]){
   await expect(connectSnapshot('memory-only',transport)).rejects.toThrow('Connection unavailable. Check access with your local operator. No actions queued.');
   expect(transport).toHaveBeenCalledTimes(1);
  }
 });
 it('rejects empty and malformed credentials before transport',async()=>{
  const transport=vi.fn();
  for(const key of ['', ' ', 'bad\r\nheader']) await expect(connectSnapshot(key,transport)).rejects.toThrow();
  expect(transport).not.toHaveBeenCalled();
 });
 it('shows synthetic one-click entry without rendering capability input or token',()=>{
  const html=renderToStaticMarkup(React.createElement(ConnectionOnboarding,{fixtureOnly:true,syntheticPreview:true,hostname:'127.0.0.1',connected:false,onConnected:()=>{},onDisconnect:()=>{}}));
  expect(html).toContain('Open test demo');expect(html).toContain('not live activity');
  expect(html).toContain('data-slot="card"');expect(html).toContain('data-slot="button"');
  expect(html).not.toContain('type="password"');expect(html).not.toContain('synthetic-local-preview-only-not-a-real-identity');
 });
 it('does not connect on render and offers disconnect without exposing a credential',()=>{
  const onConnected=vi.fn();
  const html=renderToStaticMarkup(React.createElement(ConnectionOnboarding,{fixtureOnly:true,syntheticPreview:true,hostname:'127.0.0.1',connected:true,onConnected,onDisconnect:()=>{}}));
  expect(onConnected).not.toHaveBeenCalled();expect(html).toContain('Test demo connected');expect(html).toContain('Disconnect');expect(html).not.toContain('type="password"');
 });
 it('keeps real connection access behind explicit disclosure, never demo by URL alone',()=>{
  const html=renderToStaticMarkup(React.createElement(ConnectionOnboarding,{fixtureOnly:false,syntheticPreview:true,hostname:'127.0.0.1',connected:false,onConnected:()=>{},onDisconnect:()=>{}}));
  expect(html).not.toContain('Open test demo');expect(html).toContain('<details>');expect(html).toContain('Connect your workspace');expect(html).not.toContain('Read snapshot');
 });
});
