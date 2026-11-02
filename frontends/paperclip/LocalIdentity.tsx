import React from 'react';
import {deriveInitials} from './vendor/components/Identity';
import {cn} from './vendor/lib/utils';
/* The vendored AgentAvatar asks /api/agent-avatars/... for a character image. No
   Arvyx listener serves that route, so every render produced a 404 before falling
   back to initials. This local component renders the initials directly and leaves
   the vendored bytes untouched; it keeps the vendored AgentIdentity's shape. */
export type LocalIdentityAgent={id?:string;name?:string};
const pixels={xs:20,sm:24,default:32,lg:40} as const;
export function AgentIdentity({agent,size='default',className}:{agent:LocalIdentityAgent;size?:'xs'|'sm'|'default'|'lg';className?:string}){
 const name=agent.name??'Agent';
 return <span title={name} className={cn('inline-flex min-w-0 items-center gap-1.5',className)}>
  <span data-slot="agent-avatar" aria-hidden="true" style={{width:pixels[size],height:pixels[size]}} className="inline-flex shrink-0 items-center justify-center rounded-full bg-muted text-xs text-muted-foreground">{deriveInitials(name)}</span>
  <span className={cn('truncate',size==='sm'?'text-xs':'text-sm')}>{name}</span>
 </span>;
}
