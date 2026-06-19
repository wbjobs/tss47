import os
import time
import uuid
import asyncio
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3

from database import init_db, get_db, DB_PATH
from parser import parse_pcap_file

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(title="Traffic Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


class UploadResponse(BaseModel):
    upload_id: int
    filename: str
    status: str
    packet_count: int
    min_timestamp: float
    max_timestamp: float


class UploadInfo(BaseModel):
    id: int
    filename: str
    uploaded_at: float
    packet_count: int
    status: str


@app.post("/api/upload", response_model=UploadResponse)
async def upload_pcap(file: UploadFile = File(...), db: sqlite3.Connection = Depends(get_db)):
    if not file.filename or not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap or .pcapng files are allowed")

    ext = os.path.splitext(file.filename)[1]
    safe_name = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(UPLOAD_DIR, safe_name)

    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)

    uploaded_at = time.time()
    c = db.cursor()
    c.execute("""
        INSERT INTO uploads (filename, uploaded_at, packet_count, status)
        VALUES (?, ?, 0, 'processing')
    """, (file.filename, uploaded_at))
    upload_id = c.lastrowid
    db.commit()

    loop = asyncio.get_event_loop()
    try:
        packet_count, min_ts, max_ts = await loop.run_in_executor(
            None, parse_pcap_file, file_path, upload_id
        )
    except Exception as e:
        c.execute("UPDATE uploads SET status='failed' WHERE id=?", (upload_id,))
        db.commit()
        raise HTTPException(status_code=500, detail=f"Parse error: {str(e)}")

    return UploadResponse(
        upload_id=upload_id,
        filename=file.filename,
        status="completed",
        packet_count=packet_count,
        min_timestamp=min_ts,
        max_timestamp=max_ts,
    )


@app.get("/api/uploads", response_model=List[UploadInfo])
def list_uploads(db: sqlite3.Connection = Depends(get_db)):
    c = db.cursor()
    c.execute("SELECT id, filename, uploaded_at, packet_count, status FROM uploads ORDER BY id DESC")
    rows = c.fetchall()
    return [
        UploadInfo(
            id=r["id"],
            filename=r["filename"],
            uploaded_at=r["uploaded_at"],
            packet_count=r["packet_count"],
            status=r["status"],
        )
        for r in rows
    ]


@app.get("/api/uploads/{upload_id}", response_model=UploadInfo)
def get_upload(upload_id: int, db: sqlite3.Connection = Depends(get_db)):
    c = db.cursor()
    c.execute("SELECT id, filename, uploaded_at, packet_count, status FROM uploads WHERE id=?", (upload_id,))
    r = c.fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="Upload not found")
    return UploadInfo(
        id=r["id"],
        filename=r["filename"],
        uploaded_at=r["uploaded_at"],
        packet_count=r["packet_count"],
        status=r["status"],
    )


@app.get("/api/time-range")
def get_time_range(upload_id: int, db: sqlite3.Connection = Depends(get_db)):
    c = db.cursor()
    c.execute("""
        SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts, COUNT(*) as cnt
        FROM packets WHERE upload_id=?
    """, (upload_id,))
    r = c.fetchone()
    if not r or r["cnt"] == 0:
        return {"min_timestamp": 0, "max_timestamp": 0, "count": 0}
    return {
        "min_timestamp": r["min_ts"],
        "max_timestamp": r["max_ts"],
        "count": r["cnt"],
    }


@app.get("/api/traffic/time-window")
def traffic_by_time_window(
    upload_id: int,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    window_sec: float = Query(1.0, ge=0.01),
    db: sqlite3.Connection = Depends(get_db),
):
    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "upload_id = ?"
    if start_ts is not None:
        where += " AND timestamp >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND timestamp <= ?"
        params.append(end_ts)

    c.execute(f"SELECT MIN(timestamp) as m FROM packets WHERE {where}", params)
    r = c.fetchone()
    if not r or r["m"] is None:
        return {"buckets": [], "window_sec": window_sec}

    base = r["m"]

    sql = f"""
        SELECT
            CAST((timestamp - ?) / ? AS INTEGER) as bucket_idx,
            protocol,
            COUNT(*) as packet_count,
            SUM(length) as total_bytes
        FROM packets
        WHERE {where}
        GROUP BY bucket_idx, protocol
        ORDER BY bucket_idx, protocol
    """
    all_params = [base, window_sec] + params
    c.execute(sql, all_params)
    rows = c.fetchall()

    buckets: Dict[int, Dict[str, Any]] = {}
    protocols_set = set()
    for r in rows:
        idx = r["bucket_idx"]
        proto = r["protocol"] or "OTHER"
        protocols_set.add(proto)
        if idx not in buckets:
            buckets[idx] = {"timestamp": base + idx * window_sec}
        buckets[idx][proto + "_packets"] = r["packet_count"]
        buckets[idx][proto + "_bytes"] = r["total_bytes"]

    sorted_buckets = [buckets[k] for k in sorted(buckets.keys())]
    return {
        "window_sec": window_sec,
        "protocols": sorted(protocols_set),
        "buckets": sorted_buckets,
    }


@app.get("/api/protocol/distribution")
def protocol_distribution(
    upload_id: int,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    db: sqlite3.Connection = Depends(get_db),
):
    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "upload_id = ?"
    if start_ts is not None:
        where += " AND timestamp >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND timestamp <= ?"
        params.append(end_ts)

    c.execute(f"""
        SELECT
            COALESCE(protocol, 'OTHER') as protocol,
            COUNT(*) as packet_count,
            SUM(length) as total_bytes
        FROM packets
        WHERE {where}
        GROUP BY protocol
        ORDER BY packet_count DESC
    """, params)
    rows = c.fetchall()
    total_pkts = sum(r["packet_count"] for r in rows) or 1
    total_bytes = sum(r["total_bytes"] or 0 for r in rows) or 1
    result = []
    for r in rows:
        result.append({
            "protocol": r["protocol"],
            "packet_count": r["packet_count"],
            "total_bytes": r["total_bytes"] or 0,
            "packet_percent": round(r["packet_count"] * 100.0 / total_pkts, 2),
            "bytes_percent": round((r["total_bytes"] or 0) * 100.0 / total_bytes, 2),
        })
    return {"distribution": result, "total_packets": total_pkts, "total_bytes": total_bytes}


@app.get("/api/ip-pairs/ranking")
def ip_pairs_ranking(
    upload_id: int,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    top_n: int = Query(20, ge=1, le=200),
    db: sqlite3.Connection = Depends(get_db),
):
    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "upload_id = ?"
    if start_ts is not None:
        where += " AND timestamp >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND timestamp <= ?"
        params.append(end_ts)

    c.execute(f"""
        SELECT
            src_ip,
            dst_ip,
            protocol,
            COUNT(*) as packet_count,
            SUM(length) as total_bytes
        FROM packets
        WHERE {where}
          AND src_ip IS NOT NULL
          AND dst_ip IS NOT NULL
        GROUP BY src_ip, dst_ip, protocol
        ORDER BY total_bytes DESC
        LIMIT ?
    """, params + [top_n])
    rows = c.fetchall()
    return {"ranking": [dict(r) for r in rows]}


class SessionInfo(BaseModel):
    id: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    packet_count: int
    total_bytes: int
    start_time: Optional[float]
    end_time: Optional[float]


@app.get("/api/sessions/list")
def list_sessions(
    upload_id: int,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    protocol: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: sqlite3.Connection = Depends(get_db),
):
    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "upload_id = ?"
    if start_ts is not None:
        where += " AND end_time >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND start_time <= ?"
        params.append(end_ts)
    if protocol:
        where += " AND protocol = ?"
        params.append(protocol)

    c.execute(f"""
        SELECT s.*
        FROM sessions s
        WHERE {where}
        ORDER BY total_bytes DESC
        LIMIT ? OFFSET ?
    """, params + [limit, offset])
    rows = c.fetchall()

    c.execute(f"SELECT COUNT(*) as cnt FROM sessions s WHERE {where}", params)
    cnt_r = c.fetchone()

    return {
        "total": cnt_r["cnt"] if cnt_r else 0,
        "sessions": [dict(r) for r in rows],
    }


@app.get("/api/sessions/{session_id}/packets")
def session_packets(
    session_id: str,
    upload_id: Optional[int] = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: sqlite3.Connection = Depends(get_db),
):
    c = db.cursor()
    params: List[Any] = [session_id]
    where = "session_id = ?"
    if upload_id is not None:
        where += " AND upload_id = ?"
        params.append(upload_id)

    c.execute(f"""
        SELECT p.*
        FROM packets p
        WHERE {where}
        ORDER BY timestamp ASC
        LIMIT ? OFFSET ?
    """, params + [limit, offset])
    rows = c.fetchall()
    return {"packets": [dict(r) for r in rows]}


@app.get("/api/sessions/at-time")
def sessions_at_time(
    upload_id: int,
    timestamp: float,
    tolerance_sec: float = Query(1.0, ge=0.01),
    protocol: Optional[str] = None,
    top_n: int = Query(50, ge=1, le=500),
    db: sqlite3.Connection = Depends(get_db),
):
    start = timestamp - tolerance_sec
    end = timestamp + tolerance_sec
    c = db.cursor()
    params: List[Any] = [upload_id, start, end]
    where = "upload_id = ? AND start_time <= ? AND end_time >= ?"
    if protocol:
        where += " AND protocol = ?"
        params.append(protocol)

    c.execute(f"""
        SELECT s.*
        FROM sessions s
        WHERE {where}
        ORDER BY total_bytes DESC
        LIMIT ?
    """, params + [top_n])
    rows = c.fetchall()
    return {
        "timestamp": timestamp,
        "tolerance_sec": tolerance_sec,
        "sessions": [dict(r) for r in rows],
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "db_exists": os.path.exists(DB_PATH)}
