#!/usr/bin/env python3
"""Verify tamper-evident audit log chain."""
import os
import sqlite3
import hashlib

def db_path() -> str:
    if os.path.exists('/app'):
        return '/app/data/database.db'
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'database.db')


def main() -> None:
    path = db_path()
    if not os.path.exists(path):
        print('Database not found:', path)
        return
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT id, user_id, action, table_name, query, prev_hash, entry_hash, timestamp FROM audit_log ORDER BY id"
    )
    rows = cur.fetchall()
    prev_hash = ''
    for row in rows:
        payload = f"{prev_hash}|{row['timestamp']}|{row['user_id']}|{row['action']}|{row['table_name'] or ''}|{row['query'] or ''}"
        expected = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        if row['entry_hash'] != expected:
            print('Audit chain verification FAILED at id', row['id'])
            print(' expected:', expected)
            print(' actual:  ', row['entry_hash'])
            return
        prev_hash = row['entry_hash'] or ''
    print('Audit chain verification OK. Entries:', len(rows))


if __name__ == '__main__':
    main()
