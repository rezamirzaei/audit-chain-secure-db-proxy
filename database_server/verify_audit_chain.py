#!/usr/bin/env python3
"""Verify tamper-evident audit log chain."""
import os
import hashlib

from db import connect_db, load_db_config


def main() -> None:
    cfg = load_db_config()
    if cfg.backend == "sqlite" and not os.path.exists(cfg.sqlite_path):
        print("Database not found:", cfg.sqlite_path)
        return

    db = connect_db(retries=int(os.environ.get("DB_CONNECT_RETRIES", "30")))
    rows = db.execute(
        "SELECT id, user_id, action, table_name, query, prev_hash, entry_hash, timestamp FROM audit_log ORDER BY id"
    ).fetchall()
    prev_hash = ''
    for row in rows:
        payload = f"{prev_hash}|{row['timestamp']}|{row['user_id']}|{row['action']}|{row['table_name'] or ''}|{row['query'] or ''}"
        expected = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        if row['entry_hash'] != expected:
            print('Audit chain verification FAILED at id', row['id'])
            print(' expected:', expected)
            print(' actual:  ', row['entry_hash'])
            db.close()
            return
        prev_hash = row['entry_hash'] or ''
    db.close()
    print('Audit chain verification OK. Entries:', len(rows))


if __name__ == '__main__':
    main()
