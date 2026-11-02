"""Legacy IDs/results survive an atomic migration; authority is never inferred."""
import sqlite3,json
import pytest

def legacy(db):
    db.execute('CREATE TABLE onboarding_consents(id TEXT PRIMARY KEY,sha256 TEXT,payload TEXT,expires REAL,status TEXT,result TEXT)')
    db.executemany('INSERT INTO onboarding_consents VALUES(?,?,?,?,?,?)',[
        ('prepared','d','{}',99999999999,'prepared',None),
        ('uncertain','d','{}',0,'ambiguous','{"partial":true}'),
        ('done','d','{}',0,'completed','{"agent":"original"}')]);db.commit()

def test_legacy_preserved_and_unknown_consent_fenced(tmp_path):
    from arvyx_control.authority_attempts import migrate_attempts
    db=sqlite3.connect(tmp_path/'state.db');legacy(db)
    before=db.execute('SELECT * FROM onboarding_consents').fetchall()
    migrate_attempts(db,'boot-a')
    assert db.execute('SELECT * FROM onboarding_consents').fetchall()==before
    assert set(db.execute('SELECT authority FROM authority_attempts').fetchall())=={('legacy-unknown',)}
    with pytest.raises(sqlite3.IntegrityError,match='authority'):
        db.execute("UPDATE onboarding_consents SET status='ambiguous' WHERE id='prepared'")
    db.rollback()
    db.execute("INSERT INTO onboarding_consents VALUES('new','d','{}',99999999999,'prepared',NULL)");db.commit()
    db.execute("UPDATE onboarding_consents SET status='ambiguous' WHERE id='new'");db.commit()
    assert db.execute("SELECT status FROM authority_attempts WHERE id='new'").fetchone()==('ambiguous',)
    migrate_attempts(db,'boot-b')
    assert db.execute('SELECT count(*) FROM authority_attempts').fetchone()[0]==4
    assert db.execute("SELECT result FROM onboarding_consents WHERE id='done'").fetchone()[0]=='{"agent":"original"}'


def test_restart_and_crash_never_leave_partial_schema(tmp_path):
    from arvyx_control.authority_attempts import migrate_attempts
    db=sqlite3.connect(tmp_path/'state.db');legacy(db)
    def crash(stage):
        if stage=='copied:onboarding_consents':raise RuntimeError('crash')
    with pytest.raises(RuntimeError):migrate_attempts(db,'boot-a',checkpoint=crash)
    assert db.execute("SELECT type FROM sqlite_master WHERE name='onboarding_consents'").fetchone()==('table',)
    assert db.execute('SELECT count(*) FROM onboarding_consents').fetchone()[0]==3
    migrate_attempts(db,'boot-a')
    db.execute("INSERT INTO onboarding_consents VALUES('fresh','d','{}',99999999999,'prepared',NULL)");db.commit()
    migrate_attempts(db,'boot-b')
    with pytest.raises(sqlite3.IntegrityError,match='incarnation'):
        db.execute("UPDATE onboarding_consents SET status='ambiguous' WHERE id='fresh'")


def test_old_connection_cannot_publish_new_consent_after_another_service_reopens(tmp_path):
    from arvyx_control.authority_attempts import migrate_attempts
    path=tmp_path/'state.db';first=sqlite3.connect(path);legacy(first);migrate_attempts(first,'boot-a')
    second=sqlite3.connect(path);migrate_attempts(second,'boot-b')
    with pytest.raises(sqlite3.IntegrityError,match='stale service incarnation'):
        first.execute("INSERT INTO onboarding_consents VALUES('stale','d','{}',99999999999,'prepared',NULL)")
    first.rollback();first.close();second.close()
