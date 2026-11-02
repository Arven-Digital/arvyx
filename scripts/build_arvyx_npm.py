"""Build an isolated local npm tarball from current explicit source and web assets."""
import argparse
import os

from pathlib import Path
import shutil
import subprocess
import sys

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    build_env={key:value for key,value in os.environ.items() if not key.upper().startswith(('PIP_', 'PYTHON', 'NPM_CONFIG_'))}
    build_env.update(PIP_CONFIG_FILE=os.devnull, npm_config_offline='true', npm_config_audit='false', npm_config_fund='false', npm_config_userconfig=os.devnull)
    backend=subprocess.run([sys.executable,'-I','-c',"from importlib.metadata import version; print(version('setuptools'))"],env=build_env,capture_output=True,text=True,check=False)
    if backend.returncode != 0 or backend.stdout.strip() != '84.2.1':
        parser.error('offline build requires the repository-pinned setuptools==84.2.1')
    root=Path(__file__).resolve().parents[1]
    output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    package=output/'package'
    shutil.copytree(root/'packaging/npm',package,ignore=shutil.ignore_patterns('payload','node_modules','test'))
    for name in ('LICENSE','NOTICE'):
        shutil.copy2(root/name,package/name)
    shutil.copytree(root/'licenses',package/'licenses')
    payload=package/'payload';payload.mkdir()
    # Avoid setuptools walking the dirty checkout or writing its build directories.
    source=output/'python-source';source.mkdir()
    for name in ('pyproject.toml','README.md','LICENSE','NOTICE'):
        shutil.copy2(root/name,source/name)
    shutil.copytree(root/'licenses',source/'licenses')
    for name in ('packages/arvctl/src','packages/safe-mcp-bridge/src','apps/control-center-api/src'):
        shutil.copytree(root/name,source/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.egg-info'))
    subprocess.run([sys.executable,'-I','-m','pip','--isolated','wheel',str(source),'--no-index','--no-deps','--no-build-isolation','--wheel-dir',str(payload)],env=build_env,check=True)
    # Build a copied frontend: npm ci must never remove the caller's installed
    # modules or write generated files into the dirty source checkout.
    frontend=output/'frontend-source'
    shutil.copytree(root/'frontends/paperclip',frontend,
                    ignore=shutil.ignore_patterns('node_modules','dist','dist-*','.git','__pycache__'))
    # npm has no --locked build flag. ci enforces package-lock agreement and
    # offline refuses cache misses instead of resolving/downloading new inputs.
    subprocess.run(['npm','ci','--offline','--include=dev','--ignore-scripts','--no-audit','--no-fund'],cwd=frontend,env=build_env,check=True)
    subprocess.run(['npm','run','build','--','--outDir',str(payload/'web')],cwd=frontend,
                   env=dict(build_env, VITE_AMC_FIXTURE_ONLY='false'), check=True)
    subprocess.run(['npm','pack','--offline','--ignore-scripts','--pack-destination',str(output)],cwd=package,env=build_env,check=True)
    print('LOCAL ONLY: '+str(output))

if __name__=='__main__':main()
