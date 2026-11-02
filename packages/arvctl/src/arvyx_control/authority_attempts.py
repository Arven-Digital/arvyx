"""Atomic preserving migration to a shared attempt schema in each trust domain.

Compatibility views put existing producers/consumers on canonical rows. Original
IDs, statuses, payloads and result bytes survive. Legacy authority stays unknown;
only fresh current-incarnation consent can cross an effect fence. Separate local,
organizer, remote and leaf databases retain their independent authentication.
"""
import json
SCHEMAS={
 'onboarding_consents':('id','sha256','payload','expires','status','result'),
 'session_preparations':('id','digest','payload','snapshot','expires','status','result'),
 'reviewed_actions':('id','actor','action','digest','payload','snapshot','expires','status','result'),
 'native_attempts':('id','digest','payload','snapshot','expires','status','result'),
 'organizer_requests':('id','digest','payload','expires','status','decision','result','endpoint','consent'),
 'remote_delegation_links':('local_id','remote_id','status'),
 'executor_attempts':('id','payload','status','result'),
 'bootstrap_plans':('digest','nonce','payload','status','receipt'),
}

def migrate_attempts(db,incarnation,*,checkpoint=lambda stage:None):
    if db.in_transaction:raise ValueError('migration requires dedicated idle connection')
    if not isinstance(incarnation,str) or not incarnation:raise ValueError('explicit current process incarnation required')
    db.create_function('attempt_current_incarnation',0,lambda:incarnation)
    db.execute('BEGIN IMMEDIATE')
    try:
        db.execute('''CREATE TABLE IF NOT EXISTS authority_attempts(
            namespace TEXT NOT NULL,id TEXT NOT NULL,ordinal INTEGER NOT NULL,
            record TEXT NOT NULL,authority TEXT NOT NULL,incarnation TEXT NOT NULL,
            status TEXT NOT NULL,result TEXT,PRIMARY KEY(namespace,id))''')
        db.execute('CREATE TABLE IF NOT EXISTS attempt_incarnation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value TEXT NOT NULL)')
        db.execute('INSERT OR REPLACE INTO attempt_incarnation VALUES(1,?)',(incarnation,))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS authority_bootstrap_nonce ON authority_attempts(json_extract(record,'$.nonce')) WHERE namespace='bootstrap_plans'")
        for table,columns in SCHEMAS.items():
            kind=db.execute('SELECT type FROM sqlite_master WHERE name=?',(table,)).fetchone()
            if kind is None:continue
            actual=tuple(row[1] for row in db.execute(f'PRAGMA table_info({table})'))
            if actual!=columns:raise ValueError('unsupported legacy schema: '+table)
            id_column={'remote_delegation_links':'local_id','bootstrap_plans':'digest'}.get(table,'id')
            result_column='receipt' if table=='bootstrap_plans' else 'result' if 'result' in columns else None
            if kind[0]=='table':
                for row in db.execute(f'SELECT rowid,* FROM {table}').fetchall():
                    record=dict(zip(columns,row[1:]))
                    db.execute('INSERT INTO authority_attempts VALUES(?,?,?,?,?,?,?,?)',
                        (table,record[id_column],row[0],json.dumps(record,separators=(',',':')),'legacy-unknown','',record['status'],record.get(result_column)))
                checkpoint('copied:'+table)
                db.execute(f'DROP TABLE {table}')
            else:db.execute(f'DROP VIEW {table}')
            projection=','.join(('status' if c=='status' else 'result' if c==result_column else f"json_extract(record,'$.{c}')")+f' AS {c}' for c in columns)
            db.execute(f"CREATE VIEW {table} AS SELECT {projection} FROM authority_attempts NOT INDEXED WHERE namespace='{table}' ORDER BY ordinal")
            pairs=','.join(f"'{c}',NEW.{c}" for c in columns)
            new_result=f'NEW.{result_column}' if result_column else 'NULL'
            db.execute(f'''CREATE TRIGGER {table}_insert INSTEAD OF INSERT ON {table} BEGIN
                SELECT CASE WHEN (SELECT value FROM attempt_incarnation WHERE singleton=1)!=attempt_current_incarnation()
                    THEN RAISE(ABORT,'stale service incarnation') END;
                INSERT INTO authority_attempts VALUES('{table}',NEW.{id_column},
                    (SELECT coalesce(max(ordinal),0)+1 FROM authority_attempts WHERE namespace='{table}'),
                    json_object({pairs}),'current-local-producer',attempt_current_incarnation(),NEW.status,{new_result});
                END''')
            fence="OLD.status='prepared' AND NEW.status IN ('ambiguous','completed')"
            db.execute(f'''CREATE TRIGGER {table}_update INSTEAD OF UPDATE ON {table} BEGIN
                SELECT CASE WHEN NEW.{id_column}!=OLD.{id_column} THEN RAISE(ABORT,'immutable attempt id') END;
                SELECT CASE WHEN {fence} AND
                    (SELECT authority FROM authority_attempts WHERE namespace='{table}' AND id=OLD.{id_column})!='current-local-producer'
                    THEN RAISE(ABORT,'unknown legacy authority') END;
                SELECT CASE WHEN {fence} AND
                    (SELECT incarnation FROM authority_attempts WHERE namespace='{table}' AND id=OLD.{id_column})!=(SELECT value FROM attempt_incarnation WHERE singleton=1)
                    THEN RAISE(ABORT,'stale attempt incarnation') END;
                SELECT CASE WHEN {fence} AND attempt_current_incarnation()!=(SELECT value FROM attempt_incarnation WHERE singleton=1)
                    THEN RAISE(ABORT,'stale service incarnation') END;
                UPDATE authority_attempts SET record=json_object({pairs}),status=NEW.status,result={new_result}
                    WHERE namespace='{table}' AND id=OLD.{id_column}; END''')
        checkpoint('before-commit');db.commit()
    except BaseException:db.rollback();raise
