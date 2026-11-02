import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,it,expect} from 'vitest';
import {ExternalAuthorityPanel} from './ExternalAuthorityPanel';
import {readFileSync} from 'node:fs';
describe('external access entry',()=>{
 it('has one clear demo entry and hides advanced fields',()=>{
 const html=renderToStaticMarkup(React.createElement(ExternalAuthorityPanel));
 expect(html).toContain('Open test demo');
 expect(html).toContain('<details');
 expect(html).not.toMatch(/HttpOnly|synthetic fixture|Separate external authority/);
 expect(html).not.toContain('Issue scoped grant');
 });
 it('does not render workspace onboarding on external page',()=>{
 const source=readFileSync(new URL('./main.tsx',import.meta.url),'utf8');
 expect(source).toMatch(/page!=='External delegation'&&presentationMode!=='explore'&&<ConnectionOnboarding/);
 });
});
