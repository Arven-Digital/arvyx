// Authored regression cases. NOT_EXECUTED during static-only task t_1280ea1e.
import {describe,it,expect} from 'vitest';
import {validateSnapshot} from './adapter';
import {parsePrimary} from './primary-agent';
import {projectMarkdownToText} from './vendor/shared/document-anchors';
import {parseFrontmatterMarkdown,stringifyFrontmatter} from './vendor/shared/frontmatter';
import {getAppDefinitionForUrl,resolveConnectionMethodServerUrl} from './vendor/shared/app-definitions';
import {forceLoopbackBindInCommand} from './vendor/shared/runtime-exposure/loopback-bind';
import {normalizeAgentApiKeyScope} from './vendor/shared/validators/agent';
import {connectionDisplaySecondaryHint} from './vendor/shared/humanize-connection';

describe('static repair contract regressions (not executed in static review)',()=>{
 it('rejects absent or malformed snapshot authority',()=>{
  for(const value of [null,{}, {local:{},team:{}}, {local:{},team:{availability:{tasks:true},tasks:{tasks:[null]}}}])expect(()=>validateSnapshot(value)).toThrow('Invalid workspace snapshot');
 });
 it('rejects a primary outside the returned roster',()=>{
  expect(()=>parsePrimary({primary_agent_id:'missing',primary_connected:false,revision:1,can_set_primary:true,agents:[]})).toThrow('Invalid');
 });
 it('preserves literal and escaped Markdown with offsets',()=>{
  const markdown='snake_case foo_bar unmatched* \\*literal\\* **bold**';
  const projection=projectMarkdownToText(markdown);
  expect(projection.text).toBe('snake_case foo_bar unmatched* *literal* bold');
  expect(projection.positions).toHaveLength(projection.text.length);
 });
 it('round trips leading whitespace in multiline frontmatter strings',()=>{
  const description='  first\n  second';
  expect(parseFrontmatterMarkdown(`---\n${stringifyFrontmatter({description})}\n---\n`).frontmatter.description).toBe(description);
 });
 it('does not recognize a provider hostname in an attacker path',()=>{
  expect(getAppDefinitionForUrl('https://attacker.example/.composio.dev/mcp')).toBeNull();
  expect(getAppDefinitionForUrl('https://user:pass@api.composio.dev/mcp')).toBeNull();
 });
 it('rejects arbitrary store-domain URLs',()=>{
  const method={defaults:{serverUrlTemplate:'https://{storeDomain}/api/mcp'}} as any;
  expect(resolveConnectionMethodServerUrl(method,{storeDomain:'https://attacker.example'})).toBeNull();
  expect(resolveConnectionMethodServerUrl(method,{storeDomain:'demo.myshopify.com'})).toBe('https://demo.myshopify.com/api/mcp');
 });
 it('rejects shell grammar instead of appending ignored bind arguments',()=>{
  for(const command of ['pnpm dev # ignored','pnpm dev --bind "lan"','pnpm dev && other'])expect(()=>forceLoopbackBindInCommand(command)).toThrow('Unsupported');
  expect(forceLoopbackBindInCommand('pnpm dev --bind lan')).toBe('pnpm dev --bind loopback');
 });
 it('never broadens a malformed task bridge scope to standard',()=>{
  expect(()=>normalizeAgentApiKeyScope({kind:'task_bridge'})).toThrow();
  expect(normalizeAgentApiKeyScope(undefined)).toEqual({kind:'standard'});
 });
 it('does not disclose URL userinfo in display hints',()=>{
  const hint=connectionDisplaySecondaryHint({name:'https://user:pass@example.com/private?token=secret'});
  expect(hint).toBe('hosted at example.com');
 });
});
