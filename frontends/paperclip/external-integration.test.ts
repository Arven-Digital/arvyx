import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {afterEach,describe,expect,it,vi} from 'vitest';
import {App} from './main';
afterEach(()=>vi.unstubAllGlobals());
function render(hash=''){
 vi.stubGlobal('location',{hash,hostname:'localhost'});
 return renderToStaticMarkup(React.createElement(App));
}
describe('external delegation integration',()=>{
 it('keeps Team and workspace onboarding alongside the new navigation entry',()=>{
  const html=render();expect(html).toContain('External delegation');expect(html).toContain('Connect your workspace');expect(html).toContain('>Team</button>');expect(html).toContain('>Tasks</button>');
 });
 it('waits for listener mode instead of offering fixture actions on an unknown real surface',()=>{
  const html=render('#page=external-delegation');
  expect(html).toContain('Checking presentation capabilities');expect(html).not.toContain('Open test demo');expect(html).not.toContain('Share selected work');expect(html).not.toContain('Connect your workspace');expect(html).not.toContain('Access credential');
 });
 it('does not let a synthetic query flag override unknown listener mode',()=>expect(render('#preview=synthetic&page=external-delegation')).toContain('Checking presentation capabilities'));
});
