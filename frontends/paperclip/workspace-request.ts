export const SYNTHETIC_DEMO_CAPABILITY='synthetic-local-preview-only-not-a-real-identity';
export function workspaceRequest(capability:string):RequestInit{
 if(!capability.trim()||/[\r\n]/.test(capability))throw Error('Workspace access required.');
 // Only the operator-built loopback fixture uses its HttpOnly human session.
 // The route/hash alone can never enable this authenticated transport.
 const fixture=import.meta.env.VITE_AMC_FIXTURE_ONLY==='true'&&typeof location!=='undefined'&&['127.0.0.1','localhost','[::1]'].includes(location.hostname)&&capability===SYNTHETIC_DEMO_CAPABILITY;
 return {headers:fixture?{}:{Authorization:'Bearer '+capability},credentials:fixture?'same-origin':'omit',cache:'no-store',redirect:'error'};
}
