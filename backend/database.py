import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "traffic.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def get_db_sync():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_db_sync() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                uploaded_at REAL NOT NULL,
                packet_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'processing'
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_id INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER,
                payload_size INTEGER,
                tcp_flags TEXT,
                tcp_seq INTEGER,
                tcp_ack INTEGER,
                session_id TEXT,
                FOREIGN KEY (upload_id) REFERENCES uploads(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_upload ON packets(upload_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(upload_id, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(upload_id, protocol)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(upload_id, session_id)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                upload_id INTEGER NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                start_time REAL,
                end_time REAL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_upload ON sessions(upload_id)")
        conn.commit()
