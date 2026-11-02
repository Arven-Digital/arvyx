import base64,hashlib,json,sqlite3,time
import pytest
from arvyx_control.machine_pairing import MachineIdentity

def test_plan_is_deterministic_and_receipt_is_exact_single_use(tmp_path):
    from arvyx_control.remote_bootstrap import BootstrapStore,make_plan,sign_receipt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key=Ed25519PrivateKey.generate();public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
    identity=MachineIdentity('Disposable',public)
    args=dict(machine='machine-a',identity=identity,platform='linux-x86_64',package_sha256='a'*64,native_sha256='b'*64,capabilities=['mouse-existing'],nonce='c'*32,expires=time.time()+300)
    plan=make_plan(**args);assert plan==make_plan(**args)
    assert plan['commands'][0][0]=='python3' and plan['starts_runtime'] is False
    store=BootstrapStore(tmp_path/'bootstrap.db');store.register(plan)
    receipt=sign_receipt(plan,key,remote_confirmed=True,installed_package_sha256='a'*64,installed_native_sha256='b'*64)
    with pytest.raises(PermissionError):store.accept(plan,receipt,main_approved=False)
    modified=dict(receipt,installed_native_sha256='d'*64)
    with pytest.raises(PermissionError):store.accept(plan,modified,main_approved=True)
    result=store.accept(plan,receipt,main_approved=True)
    assert result['verified_installation_receipt'] and result['runtime_authorized'] is False
    with pytest.raises(ValueError):store.accept(plan,receipt,main_approved=True)
    store.close()


def test_unsupported_platform_and_expired_or_unsigned_receipt_refused(tmp_path):
    from arvyx_control.remote_bootstrap import make_plan,BootstrapStore
    identity=MachineIdentity('Test',base64.b64encode(b'x'*32).decode())
    with pytest.raises(ValueError):make_plan(machine='m',identity=identity,platform='darwin-arm64',package_sha256='a'*64,native_sha256='b'*64,capabilities=['onboarding-v1'],nonce='c'*32,expires=time.time()+300)
