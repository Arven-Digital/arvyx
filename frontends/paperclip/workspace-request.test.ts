import {it,expect,vi,afterEach} from 'vitest';
import {workspaceRequest} from './workspace-request';
import {SYNTHETIC_DEMO_CAPABILITY} from './connection';
afterEach(()=>{vi.unstubAllEnvs();vi.unstubAllGlobals()});
it('uses only the explicit loopback fixture human session without bearer credentials',()=>{vi.stubEnv('VITE_AMC_FIXTURE_ONLY','true');vi.stubGlobal('location',{hostname:'127.0.0.1'});expect(workspaceRequest(SYNTHETIC_DEMO_CAPABILITY)).toMatchObject({credentials:'same-origin',headers:{}});expect(workspaceRequest('operator')).toMatchObject({credentials:'omit',headers:{Authorization:'Bearer operator'}})});
it('never enables fixture cookies from route intent or a foreign host',()=>{vi.stubEnv('VITE_AMC_FIXTURE_ONLY','false');vi.stubGlobal('location',{hostname:'127.0.0.1'});expect(workspaceRequest(SYNTHETIC_DEMO_CAPABILITY).credentials).toBe('omit');vi.stubEnv('VITE_AMC_FIXTURE_ONLY','true');vi.stubGlobal('location',{hostname:'attacker.example'});expect(workspaceRequest(SYNTHETIC_DEMO_CAPABILITY).credentials).toBe('omit')});
