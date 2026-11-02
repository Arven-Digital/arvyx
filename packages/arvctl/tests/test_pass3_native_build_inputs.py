import runpy,json
from pathlib import Path
import pytest
build=runpy.run_path(str(Path(__file__).resolve().parents[3]/'scripts/build_arvyx_native.py'))

def test_linker_sdk_roots_and_tools_are_hashed_without_building(tmp_path):
    root=tmp_path/'toolchain';root.mkdir();sdk=tmp_path/'sdk';sdk.mkdir();(sdk/'header.h').write_text('first')
    tools={}
    for name in ('patch','cc','ar','ld','pkg-config','cmake'):
        file=root/name;file.write_text('disposable tool bytes');tools[name]=str(file)
    spec=tmp_path/'inputs.json';value=dict(tools=tools,toolchain_roots=[str(root)],sdk_roots=[str(sdk)]);spec.write_text(json.dumps(value))
    first=build['build_inputs'](spec);(sdk/'header.h').write_text('changed')
    assert build['build_inputs'](spec)!=first
    value['tools']['ld']=str(tmp_path/'outside');Path(value['tools']['ld']).write_text('outside');spec.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='outside'):build['build_inputs'](spec)
