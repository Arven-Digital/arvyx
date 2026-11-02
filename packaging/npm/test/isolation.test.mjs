import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,symlinkSync,existsSync,rmSync,openSync,closeSync,readFileSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const sourceCli=fileURLToPath(new URL('../bin/arvyx.mjs',import.meta.url));
function capture(program,args,options={}){
 const temp=mkdtempSync(join(tmpdir(),'arvyx-capture-')),out=join(temp,'out'),err=join(temp,'err');
 const outfd=openSync(out,'w'),errfd=openSync(err,'w');
 try{const p=spawnSync(program,args,{...options,stdio:['ignore',outfd,errfd]});assert.ifError(p.error);return {...p,stdout:readFileSync(out,'utf8'),stderr:readFileSync(err,'utf8')}}
 finally{closeSync(outfd);closeSync(errfd);rmSync(temp,{recursive:true,force:true})}
}
function launcher(root){const bin=join(root,'package/bin');mkdirSync(bin,{recursive:true});mkdirSync(join(root,'package/payload'),{recursive:true});const cli=join(bin,'arvyx.mjs');copyFileSync(sourceCli,cli);return cli}

for(const command of ['doctor','amc','web'])test(`${command} rejects incomplete setup without loading caller modules`,()=>{
 const root=mkdtempSync(join(tmpdir(),'arvyx-isolation-'));
 try{
 const cli=launcher(root);
 const prefix=join(root,'prefix'),cwd=join(root,'hostile');mkdirSync(join(prefix,'bin'),{recursive:true});mkdirSync(join(cwd,'arvyx_control'),{recursive:true});
 const python=capture('python3',['-I','-c','import sys; print(sys.executable)'],{encoding:'utf8'}).stdout.trim();
 symlinkSync(python,join(prefix,'bin/python'));
 const marker=join(root,'executed');
 const code=`from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('caller module executed')\n`;
 writeFileSync(join(cwd,'json.py'),code);writeFileSync(join(cwd,'arvyx_control/__init__.py'),code);
 const p=capture(process.execPath,[cli,command,'--prefix',prefix,...(command==='amc'?['--help']:[])],{cwd,encoding:'utf8'});
 assert.equal(p.status,2);assert.match(p.stderr,/Setup incomplete/);
 assert.equal(existsSync(marker),false,p.stdout+p.stderr);
 }finally{rmSync(root,{recursive:true,force:true})}
});
for(const flag of ['--frontend=/tmp/foreign','--front=/tmp/foreign','--frontend','--front'])test(`web rejects packaged frontend override ${flag}`,()=>{
 const root=mkdtempSync(join(tmpdir(),'arvyx-args-'));
 try{const cli=launcher(root);mkdirSync(join(root,'bin'));writeFileSync(join(root,'bin/python'),'');
 const p=capture(process.execPath,[cli,'web','--prefix',root,flag],{encoding:'utf8'});
 assert.equal(p.status,2);assert.match(p.stderr,/bundled frontend/);
 }finally{rmSync(root,{recursive:true,force:true})}
});
