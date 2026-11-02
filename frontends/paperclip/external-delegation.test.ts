import {describe,it,expect} from 'vitest';
import {prepareDelegation, unavailableDelegationAdapter, delegationState, type DelegationDraft} from './external-delegation';
const draft:DelegationDraft={recipientId:'grok-local',kind:'workspace',resource:'project-alpha',operations:['read'],expiryHours:24,acknowledged:true};
const recipients=[{id:'grok-local',label:'Grok local',location:'local' as const}];
describe('external delegation boundary',()=>{
 it('preserves recipient and explicit 24 hour read-only scope',()=>{const p=prepareDelegation(draft,recipients,0);expect(p.recipientId).toBe('grok-local');expect(p.expiresAt).toBe('1970-01-02T00:00:00.000Z');expect(p.operations).toEqual(['read']);expect(p.exclusions).toContain('Secrets and private/family material');});
 it('rejects missing recipient, scope, permissions and acknowledgement',()=>{for(const patch of [{recipientId:'cloud-imposter'},{resource:' '},{operations:[]},{acknowledged:false},{expiryHours:0},{expiryHours:25}]) expect(()=>prepareDelegation({...draft,...patch},recipients,0)).toThrow();});
 it('skill links grant no implicit access',()=>expect(prepareDelegation({...draft,kind:'skill',resource:'SKILL.md'},recipients,0).exclusions).toContain('Skill links and parent directories'));
 it('never fabricates backend success',async()=>{expect(unavailableDelegationAdapter.available).toBe(false);await expect(unavailableDelegationAdapter.issue(prepareDelegation(draft,recipients,0))).rejects.toThrow('not wired');await expect(unavailableDelegationAdapter.revoke('id')).rejects.toThrow('not wired');await expect(unavailableDelegationAdapter.list()).rejects.toThrow('not wired');});
 it('derives expiry without overriding revocation',()=>{expect(delegationState({state:'active',expiresAt:'1970-01-02T00:00:00.000Z'},86400000)).toBe('expired');expect(delegationState({state:'revoked',expiresAt:'1970-01-02T00:00:00.000Z'},86400000)).toBe('revoked');});
});
