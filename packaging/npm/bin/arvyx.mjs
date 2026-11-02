#!/usr/bin/env node
import {spawnSync} from 'node:child_process';
import {existsSync, mkdirSync, readFileSync, readdirSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, lstatSync} from 'node:fs';
import {dirname, resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {devNull} from 'node:os';
const payload=resolve(dirname(fileURLToPath(import.meta.url)), '../payload');
const args=process.argv.slice(2), command=args.shift();
function fail(message){console.error(message);process.exit(2)}
function run(program,argv){
 const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!/^PIP_|^PYTHON/i.test(key)));
 env.PIP_CONFIG_FILE=devNull;
 const p=spawnSync(program,['-I',...argv],{cwd:payload,stdio:'inherit',env});
 if(p.error)fail(p.error.message);if(p.status!==0)process.exit(p.status??2);
}
function packageIdentity(){
 const wheels=readdirSync(payload).filter(x=>x.endsWith('.whl'));
 if(wheels.length!==1)fail('Exactly one bundled wheel is required.');
 return {wheel:wheels[0],wheel_sha256:createHash('sha256').update(readFileSync(join(payload,wheels[0]))).digest('hex'),prefix};
}
function verifyPrefix(){
 if(!existsSync(py))fail('Run explicit setup first.');
 run(py,['-c',`import importlib.util, pathlib, sys, sysconfig
expected = pathlib.Path(sys.argv[1]).resolve()
if pathlib.Path(sys.prefix).resolve() != expected or sys.prefix == sys.base_prefix:
    raise SystemExit('requested virtualenv provenance mismatch')
purelib = pathlib.Path(sysconfig.get_path('purelib')).resolve()
if not purelib.is_relative_to(expected):
    raise SystemExit('site-packages is outside requested prefix')
for name in ('arvyx_control', 'safe_mcp_bridge', 'arvyx_control_center_api'):
    spec = importlib.util.find_spec(name)
    if spec is None or not spec.origin or not pathlib.Path(spec.origin).resolve().is_relative_to(purelib):
        raise SystemExit('installed package provenance mismatch: ' + name)
`,prefix]);
}
function requireComplete(){
 const intent=readIntent(), identity=packageIdentity();
 if(Object.entries(identity).some(([key,value])=>intent[key]!==value))fail('Setup provenance does not match this prefix and bundled wheel.');
 verifyPrefix();
 if(intent.native_requested){
  if(!existsSync(join(prefix,'native')))fail('Setup incomplete: requested native component missing.');
  run(py,['-m','arvyx_control.native_install','--check',join(prefix,'native'),'--require-capability',intent.native_capability]);
 }
 return intent;
}
const intentName='setup-intent.json';
function syncDirectory(path){const fd=openSync(path,'r');try{fsyncSync(fd)}finally{closeSync(fd)}}
function writeIntent(record,complete=false){
 const target=join(prefix,intentName), pending=join(prefix,'setup-intent.complete.tmp');
 const fd=openSync(complete?pending:target,'wx',0o600);
 try{writeFileSync(fd,JSON.stringify(record)+'\n');fsyncSync(fd)}finally{closeSync(fd)}
 if(complete)renameSync(pending,target);
 syncDirectory(prefix);
}
function readIntent(){
 try{
  const path=join(prefix,intentName), info=lstatSync(path);
  if(!info.isFile()||info.isSymbolicLink()||info.size>4096)throw Error();
  const record=JSON.parse(readFileSync(path,'utf8'));
  if(record.version!==2||typeof record.native_requested!=='boolean'||record.state!=='complete')throw Error();
  if(record.native_requested?!['mouse-existing','onboarding-v1'].includes(record.native_capability):record.native_capability!==null)throw Error();
  return record;
 }catch{fail('Setup incomplete or intent missing/invalid; retained prefix requires explicit recovery into a new prefix.');}
}
if(!command||command==='--help'){console.log('Arvyx local package: setup --prefix NEW_DIRECTORY [--python python3] [--native-binary FILE --native-receipt FILE --native-capability mouse-existing|onboarding-v1]; doctor --prefix DIRECTORY; amc --prefix DIRECTORY [CLI args]; web --prefix DIRECTORY [existing-owner options]. Native binary is not bundled. No provider starts during setup.');process.exit(0)}
const at=args.indexOf('--prefix');if(at<0||!args[at+1])fail('An explicit --prefix is required.');
const prefix=resolve(args[at+1]);args.splice(at,2);
const py=join(prefix,process.platform==='win32'?'Scripts/python.exe':'bin/python');
if(command==='setup'){
 let python='python3';const i=args.indexOf('--python');if(i>=0){
  python=args[i+1];args.splice(i,2);
  if(!python||python.startsWith('--'))fail('Missing --python value.');
  // Preserve PATH lookup for bare commands; anchor explicit paths to the caller.
  if(python.includes('/')||python.includes('\\'))python=resolve(python);
 }
 const take=(flag)=>{const at=args.indexOf(flag);if(at<0)return null;const value=args[at+1];args.splice(at,2);if(!value||value.startsWith('--'))fail('Missing setup option value.');return resolve(value)};
 const capabilityAt=args.indexOf('--native-capability');
 let nativeCapability='mouse-existing';
 if(capabilityAt>=0){nativeCapability=args[capabilityAt+1];args.splice(capabilityAt,2)}
 if(!['mouse-existing','onboarding-v1'].includes(nativeCapability))fail('Unknown native capability.');
 const native=take('--native-binary'), receipt=take('--native-receipt');
 if(capabilityAt>=0&&!native)fail('Native capability requires explicit native binary and receipt.');
 if(Boolean(native)!==Boolean(receipt))fail('Supply both --native-binary and --native-receipt.');
 if(native&&(!existsSync(native)||!existsSync(receipt)))fail('Explicit native binary and receipt files must exist.');
 if(args.length||!python)fail('Unexpected setup arguments.');
 if(existsSync(prefix))fail('Setup destination already exists; nothing overwritten.');
 const wheel=readdirSync(payload).filter(x=>x.endsWith('.whl'));if(wheel.length!==1||!existsSync(join(payload,'web/index.html')))fail('Incomplete local package.');
 run(python,['-c','import sys; assert sys.version_info >= (3,11), "Python >=3.11 required"']);
 // Reserve a NEW private prefix before venv inherits the caller's umask.
 mkdirSync(dirname(prefix),{recursive:true,mode:0o700});
 try{mkdirSync(prefix,{mode:0o700})}catch{fail('Setup destination must be new and private.')}
 syncDirectory(dirname(prefix));
 const intent={version:2,...packageIdentity(),native_requested:Boolean(native),native_capability:native?nativeCapability:null,state:'incomplete'};
 writeIntent(intent);
 run(python,['-m','venv',prefix]);
 run(py,['-m','pip','--isolated','install','--no-index','--no-deps','--no-user','--prefix',prefix,'--ignore-installed',join(payload,wheel[0])]);
 verifyPrefix();
 if(native)run(py,['-m','arvyx_control.native_install','--binary',native,'--receipt',receipt,'--destination',join(prefix,'native'),'--require-capability',nativeCapability]);
 writeIntent({...intent,state:'complete'},true);
 console.log('Setup complete: Python CLI and web assets installed. Optional approved native bytes are installed only when explicitly supplied; no native owner starts. Runtime launch, remote and root execution need separately approved executors.');
}else if(command==='doctor'){
 if(args.length)fail('Unexpected doctor arguments.');
 const intent=requireComplete();
 if(intent.native_requested&&!existsSync(join(prefix,'native')))fail('Setup incomplete: requested native component missing.');
 if(!existsSync(py))fail('Run explicit setup first.');
 run(py,['-c','import arvyx_control.onboarding_cli, arvyx_control.cockpit_local; print("Python package import OK")']);
 if(!existsSync(join(payload,'web/index.html')))fail('Web assets missing.');
 if(existsSync(join(prefix,'native')))run(py,['-m','arvyx_control.native_install','--check',join(prefix,'native'),'--require-capability',intent.native_requested?intent.native_capability:'mouse-existing']);
 console.log('Web assets OK. Optional native bytes are checked when present; no live reachability or native runtime acceptance claimed.');
}else if(command==='amc'){
 requireComplete();run(py,['-m','arvyx_control.onboarding_cli',...args]);
}else if(command==='web'){
 if(args.some(arg=>arg.startsWith('--')&&'--frontend'.startsWith(arg.split('=')[0])))fail('Packaged web command uses its bundled frontend.');
 requireComplete();
 run(py,['-m','arvyx_control.cockpit_local','--frontend',join(payload,'web'),...args]);
}else fail('Unknown command. Use --help.');
