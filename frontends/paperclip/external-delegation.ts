export type Recipient = {id:string;label:string;location:'cloud'|'local'};
export type ResourceKind = 'task'|'prompt'|'skill'|'artifact'|'artifacts'|'workspace';
export type Operation = 'read'|'submit-result';
export type DelegationState = 'active'|'revoked'|'expired'|'unavailable';
export interface DelegationDraft {recipientId:string;kind:ResourceKind;resource:string;operations:Operation[];expiryHours:number;acknowledged:boolean}
export interface DelegationRequest {recipientId:string;kind:ResourceKind;resource:string;operations:Operation[];expiresAt:string;exclusions:readonly string[]}
export interface DelegationRecord extends DelegationRequest {grantedOperations?:string[];resources?:string[];id:string;issuer:string;createdAt:string;state:DelegationState}
export const exclusions = ['Secrets and private/family material','Other tasks, projects and squad memory','Host filesystem, shell execution and write access','Skill links and parent directories'] as const;
export const disclosureWarning = 'Revocation stops future access; it cannot erase previously disclosed copies. Excluded content means review coverage is incomplete.';
export function prepareDelegation(draft:DelegationDraft,recipients:readonly Recipient[],now=Date.now()):DelegationRequest {
 if(!recipients.some(r=>r.id===draft.recipientId)) throw new Error('Choose an explicit registered recipient.');
 if(!['task','prompt','skill','artifact','artifacts','workspace'].includes(draft.kind)||!draft.resource.trim()) throw new Error('Select explicit content or a named resource.');
 if(!draft.operations.length||draft.operations.some(o=>!['read','submit-result'].includes(o))) throw new Error('Choose permitted operations.');
 if(!Number.isFinite(draft.expiryHours)||draft.expiryHours<=0||draft.expiryHours>24) throw new Error('Expiry must be within 24 hours.');
 if(!draft.acknowledged) throw new Error('Acknowledge disclosure and exclusions.');
 return {recipientId:draft.recipientId,kind:draft.kind,resource:draft.resource,operations:[...new Set(draft.operations)],expiresAt:new Date(now+draft.expiryHours*3600000).toISOString(),exclusions:[...exclusions]};
}
export function delegationState(record:Pick<DelegationRecord,'state'|'expiresAt'>,now=Date.now()):DelegationState {
 return record.state==='unavailable'?'unavailable':record.state==='revoked'?'revoked':record.state==='expired'||!Number.isFinite(Date.parse(record.expiresAt))||Date.parse(record.expiresAt)<=now?'expired':'active';
}
/** Implementations must authorize exports, enforce manifest exclusions and read back mutations before resolving. */
export interface DelegationAuditPage {grant_id:string;coverage:'scope-indexed-events-only';items:{sequence:number;timestamp:string;event:string;details:Record<string,string|boolean>}[];has_more:boolean;next_cursor:string|null}
export interface ExternalDelegationAdapter {available:boolean;unavailableReason?:string;list():Promise<DelegationRecord[]>;inspect?(id:string):Promise<DelegationRecord>;issue(request:DelegationRequest):Promise<DelegationRecord>;revoke(id:string):Promise<DelegationRecord>;audit?(id:string,cursor?:string):Promise<DelegationAuditPage>}
const unavailable = async():Promise<never>=>{throw new Error('External delegation authority is not wired. No access has been granted or revoked.');};
export const unavailableDelegationAdapter:ExternalDelegationAdapter={available:false,unavailableReason:'External delegation authority is not wired. Draft preview only; no export or revoke requests are sent.',list:unavailable,issue:unavailable,revoke:unavailable};
