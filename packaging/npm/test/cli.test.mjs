import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const cli=fileURLToPath(new URL('../bin/arvyx.mjs',import.meta.url));
test('help discloses missing native runtime',()=>{const p=spawnSync(process.execPath,[cli,'--help'],{encoding:'utf8'});assert.equal(p.status,0);assert.match(p.stdout,/Native binary is not bundled/)});
test('setup requires explicit new destination',()=>{const p=spawnSync(process.execPath,[cli,'setup'],{encoding:'utf8'});assert.equal(p.status,2);assert.match(p.stderr,/explicit --prefix/)});
test('native terminal never claims setup success',()=>{const p=spawnSync(process.execPath,[cli,'amc','--prefix','/nonexistent-arvyx-test','terminal'],{encoding:'utf8'});assert.equal(p.status,2);assert.match(p.stderr,/Setup incomplete/)});
