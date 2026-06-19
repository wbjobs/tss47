import sqlite3
import os
import csv
import shutil
import tempfile
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "traffic.db")


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def get_db_sync(timeout: int = 120):
    conn = sqlite3.connect(DB_PATH, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA cache_size=-200000")
    conn.execute("PRAGMA temp_store=MEMORY")
    try:
        yield conn
    finally:
        conn.commit()
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
                status TEXT DEFAULT 'processing',
                min_timestamp REAL,
                max_timestamp REAL,
                task_id TEXT
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
                session_id TEXT
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
        c.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                upload_id INTEGER,
                status TEXT DEFAULT 'pending',
                progress REAL DEFAULT 0,
                message TEXT,
                error_message TEXT,
                created_at REAL,
                updated_at REAL,
                result_data TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_tasks_upload ON tasks(upload_id)")
        conn.commit()


PACKET_CSV_COLUMNS = [
    "upload_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "length", "payload_size", "tcp_flags", "tcp_seq", "tcp_ack", "session_id"
]


def import_packets_from_csv(csv_path: str, upload_id: int) -> int:
    """通过临时 CSV 文件批量导入 packets（先写 CSV，再用 .import / pandas 一次性导入）。
    返回导入的行数。
    """
    if not os.path.exists(csv_path):
        return 0
    try:
        import pandas as pd
        import numpy as np

        chunksize = 200000
        rows_imported = 0
        with get_db_sync(timeout=300) as conn:
            for chunk in pd.read_csv(csv_path, chunksize=chunksize, dtype={
                "src_ip": "object", "dst_ip": "object", "protocol": "object",
                "tcp_flags": "object", "session_id": "object",
                "src_port": "Int64", "dst_port": "Int64",
                "tcp_seq": "Int64", "tcp_ack": "Int64",
                "timestamp": "float64", "length": "Int64", "payload_size": "Int64",
                "upload_id": "int64",
            }, keep_default_na=False, na_values=[""]):
                chunk["upload_id"] = upload_id
                for col in ["src_port", "dst_port", "tcp_seq", "tcp_ack", "length", "payload_size"]:
                    chunk[col] = chunk[col].astype("Int64")
                chunk.to_sql(
                    "packets", conn, if_exists="append", index=False,
                    method="multi", chunksize=5000,
                )
                rows_imported += len(chunk)
        return rows_imported
    except ImportError:
        pass

    count = 0
    batch = []
    BATCH = 20000
    with get_db_sync(timeout=300) as conn:
        c = conn.cursor()
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                batch.append((
                    upload_id,
                    float(row["timestamp"]) if row["timestamp"] else 0,
                    row.get("src_ip") or None,
                    row.get("dst_ip") or None,
                    int(row["src_port"]) if row.get("src_port") else None,
                    int(row["dst_port"]) if row.get("dst_port") else None,
                    row.get("protocol") or None,
                    int(row["length"]) if row.get("length") else None,
                    int(row["payload_size"]) if row.get("payload_size") else None,
                    row.get("tcp_flags") or None,
                    int(row["tcp_seq"]) if row.get("tcp_seq") else None,
                    int(row["tcp_ack"]) if row.get("tcp_ack") else None,
                    row.get("session_id") or None,
                ))
                if len(batch) >= BATCH:
                    c.executemany("""
                        INSERT INTO packets
                        (upload_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                         protocol, length, payload_size, tcp_flags, tcp_seq, tcp_ack, session_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                    count += len(batch)
                    batch.clear()
            if batch:
                c.executemany("""
                    INSERT INTO packets
                    (upload_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                     protocol, length, payload_size, tcp_flags, tcp_seq, tcp_ack, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch)
                count += len(batch)
    return count


def aggregate_sessions_from_db(upload_id: int) -> tuple:
    """根据已导入的 packets 表，通过 SQL 聚合一次性构建 sessions 表。"""
    with get_db_sync(timeout=300) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE upload_id=?", (upload_id,))
        c.execute("""
            INSERT OR REPLACE INTO sessions
            (id, upload_id, src_ip, dst_ip, src_port, dst_port, protocol,
             packet_count, total_bytes, start_time, end_time)
            SELECT
                session_id as id,
                upload_id,
                MIN(src_ip) as src_ip,
                MIN(dst_ip) as dst_ip,
                MIN(src_port) as src_port,
                MIN(dst_port) as dst_port,
                protocol,
                COUNT(*) as packet_count,
                COALESCE(SUM(length), 0) as total_bytes,
                MIN(timestamp) as start_time,
                MAX(timestamp) as end_time
            FROM packets
            WHERE upload_id = ? AND session_id IS NOT NULL
            GROUP BY session_id
        """, (upload_id,))
        c.execute("""
            SELECT MIN(timestamp) as mn, MAX(timestamp) as mx, COUNT(*) as cnt
            FROM packets WHERE upload_id = ?
        """, (upload_id,))
        row = c.fetchone()
        min_ts = row["mn"] if row else 0
        max_ts = row["mx"] if row else 0
        cnt = row["cnt"] if row else 0
        c.execute("""
            UPDATE uploads SET packet_count=?, status='completed',
                min_timestamp=?, max_timestamp=?
            WHERE id=?
        """, (cnt, min_ts, max_ts, upload_id))
        conn.commit()
    return cnt, min_ts or 0, max_ts or 0

