import {describe,it,expect} from 'vitest';
import {readRoute,taskRoute} from './navigation';
describe('local task navigation',()=>{
 it('reads an initial task deep link',()=>expect(readRoute('#task=task_123').task).toBe('task_123'));
 it('preserves the synthetic label when opening and reloading a task',()=>expect(readRoute(taskRoute('task_123',true))).toEqual({task:'task_123',synthetic:true}));
 it('closes details without losing preview identity',()=>expect(readRoute(taskRoute('',true))).toEqual({task:'',synthetic:true}));
 it('does not interpret arbitrary hashes as task IDs',()=>expect(readRoute('#preview=synthetic').task).toBe(''));
 it('round trips reserved characters without adding route parameters',()=>expect(readRoute(taskRoute('a&preview=synthetic/%',false))).toEqual({task:'a&preview=synthetic/%',synthetic:false}));
 it('does not throw for malformed percent escapes',()=>expect(()=>readRoute('#task=%ZZ')).not.toThrow());
});
