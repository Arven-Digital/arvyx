import {it,expect} from 'vitest';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {onboardingRequest} from './public-onboarding';
import {DiscoveryWarning} from './PublicOnboarding';
it('never fabricates connector availability and retains safe location',async()=>{
 const transport=async(url:any)=>new Response(JSON.stringify(String(url).endsWith('/discover')?{candidates:[{id:'unsupported',available:false,location:'~/.hermes'}],truncated:true}:String(url).endsWith('/agents')?{items:[]}:{harnesses:[]}));
 const data=await onboardingRequest('x','',undefined,transport);
 expect(data.candidates[0].available).toBe(false);
 expect(data.candidates[0].location).toBe('~/.hermes');
 expect(data.truncated).toBe(true);
});
it('renders a bounded warning only for incomplete discovery',()=>{
 expect(renderToStaticMarkup(React.createElement(DiscoveryWarning,{truncated:true}))).toContain('Discovery is incomplete');
 expect(renderToStaticMarkup(React.createElement(DiscoveryWarning,{truncated:false}))).toBe('');
});
it('preserves server mode, exact connected targets and incomplete reasons',async()=>{
 const target={machine_id:'machine',agent_id:'agent',workspace_id:'profile',connection_id:'exact'};
 const transport=(async(url:any)=>new Response(JSON.stringify(String(url).endsWith('/discover')?{candidates:[],truncated:false,incomplete:true,incomplete_reasons:['unreadable_location'],mode:'real-local'}:String(url).endsWith('/capabilities')?{mode:'real-local',harnesses:[],creation_available:true,creation_mode:'clean_metadata_only',manual_connection:true}:String(url).endsWith('/targets')?{items:[target]}:{items:[]}))) as typeof fetch;
 const data=await onboardingRequest('x','',undefined,transport);
 expect(data.mode).toBe('real-local');expect(data.targets).toEqual([target]);expect(data.incomplete).toBe(true);expect(data.manual_connection).toBe(true);
});
