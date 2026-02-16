import os
import sqlite3
from typing import List, Optional

DB_PATH = os.environ.get('QSEC2_DB', os.path.join('data', 'qsec2.db'))


def init_db(db_path: Optional[str] = None):
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS room_users (
        room_id TEXT,
        username TEXT,
        UNIQUE(room_id, username)
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS room_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()
    return path


def _connect():
    return sqlite3.connect(DB_PATH)


def add_user(room: str, username: str):
    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute('INSERT OR IGNORE INTO room_users(room_id, username) VALUES (?, ?)', (room, username))
        conn.commit()
    finally:
        conn.close()


def add_log(room: str, message: str):
    conn = _connect()
    cur = conn.cursor()
    cur.execute('INSERT INTO room_logs(room_id, message) VALUES (?, ?)', (room, message))
    conn.commit()
    rowid = cur.lastrowid
    # fetch the inserted row to return structured info
    cur.execute('SELECT id, message, created_at FROM room_logs WHERE id = ?', (rowid,))
    r = cur.fetchone()
    conn.close()
    if r:
        return {'id': r[0], 'message': r[1], 'created_at': r[2]}
    return None


def get_logs(room: str, limit: int = 100, since_id: int = None):
    conn = _connect()
    cur = conn.cursor()
    if since_id is None:
        cur.execute('SELECT id, message, created_at FROM room_logs WHERE room_id = ? ORDER BY id DESC LIMIT ?', (room, limit))
    else:
        cur.execute('SELECT id, message, created_at FROM room_logs WHERE room_id = ? AND id > ? ORDER BY id DESC LIMIT ?', (room, since_id, limit))
    rows = cur.fetchall()
    conn.close()
    # Return in chronological order (oldest first) and include id
    return [{'id': r[0], 'message': r[1], 'created_at': r[2]} for r in reversed(rows)]
