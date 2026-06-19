import os
import time
import uuid
import asyncio
import threading
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3

from database import init_db, get_db, DB_PATH
from parser import parse_pcap_file
from task_queue import (
    enqueue_parse_task,
    get_task_progress,
    mark_task_failed,
    mark_task_completed,
    update_task_progress,
    RQ_AVAILABLE,
    get_queue,
)
from filters import (
    PACKET_ALLOWED_FIELDS,
    SESSION_ALLOWED_FIELDS,
    parse_filters,
    parse_filters_from_query,
)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

_sync_parse_threads: Dict[str, threading.Thread] = {}

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


class UploadAcceptedResponse(BaseModel):
    upload_id: int
    task_id: str
    filename: str
    mode: str
    note: str = ""


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    progress: float
    message: str
    upload_id: Optional[int] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    updated_at: Optional[float] = None


class UploadInfo(BaseModel):
    id: int
    filename: str
    uploaded_at: float
    packet_count: int
    status: str
    min_timestamp: Optional[float] = None
    max_timestamp: Optional[float] = None


def _run_sync_parse_task(file_path: str, upload_id: int,
                         filename: str, task_id: str):
    """在单独线程中执行解析（RQ 不可用时的回退方案），并写入进度。"""
    from parser import _parse_with_tshark, _parse_with_scapy
    try:
        def cb(pct: float, msg: str):
            try:
                update_task_progress(task_id, pct, msg, {"filename": filename})
            except Exception:
                pass

        ok, cnt, mn, mx = _parse_with_tshark(file_path, upload_id, cb)
        if not ok:
            ok, cnt, mn, mx = _parse_with_scapy(file_path, upload_id, cb)
        if not ok:
            raise RuntimeError("tshark 和 scapy 均解析失败")

        result = {
            "upload_id": upload_id,
            "filename": filename,
            "packet_count": cnt,
            "min_timestamp": mn,
            "max_timestamp": mx,
        }
        mark_task_completed(task_id, f"✅ 解析完成，共 {cnt} 个包", result)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        mark_task_failed(task_id, f"{e}\n{tb}")
    finally:
        _sync_parse_threads.pop(task_id, None)


@app.post("/api/upload", response_model=UploadAcceptedResponse)
async def upload_pcap(file: UploadFile = File(...), db: sqlite3.Connection = Depends(get_db)):
    if not file.filename or not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap or .pcapng files are allowed")

    ext = os.path.splitext(file.filename)[1]
    safe_name = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(UPLOAD_DIR, safe_name)

    size = 0
    chunk_size = 1024 * 1024 * 8
    with open(file_path, "wb") as f:
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)
            size += len(chunk)

    uploaded_at = time.time()
    c = db.cursor()
    c.execute("""
        INSERT INTO uploads (filename, uploaded_at, packet_count, status)
        VALUES (?, ?, 0, 'processing')
    """, (file.filename, uploaded_at))
    upload_id = c.lastrowid
    db.commit()

    enq = enqueue_parse_task(file_path, upload_id, file.filename)
    task_id = enq["task_id"]
    mode = enq["mode"]
    note = enq.get("note", "")

    c.execute("UPDATE uploads SET task_id=? WHERE id=?", (task_id, upload_id))
    db.commit()

    with get_db() as _conn:
        pass
    try:
        with sqlite3.connect(DB_PATH, timeout=60) as conn:
            cc = conn.cursor()
            cc.execute("""
                INSERT INTO tasks (id, upload_id, status, progress, message, created_at, updated_at)
                VALUES (?, ?, 'pending', 0, '任务已入队', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    upload_id=excluded.upload_id,
                    status='pending',
                    progress=0,
                    message='任务已入队',
                    updated_at=excluded.updated_at
            """, (task_id, upload_id, time.time(), time.time()))
            conn.commit()
    except Exception:
        pass

    if mode == "sync_fallback":
        t = threading.Thread(
            target=_run_sync_parse_task,
            args=(file_path, upload_id, file.filename, task_id),
            daemon=True,
        )
        t.start()
        _sync_parse_threads[task_id] = t
        note = "Redis 未连接，已回退到内置线程池异步解析。如需更高并发性能，请启动 Redis 与 RQ Worker。"

    return UploadAcceptedResponse(
        upload_id=upload_id,
        task_id=task_id,
        filename=file.filename,
        mode=mode,
        note=note,
    )


@app.get("/api/tasks/{task_id}/status", response_model=TaskStatusResponse)
def get_task_status(task_id: str, db: sqlite3.Connection = Depends(get_db)):
    progress = get_task_progress(task_id)
    status = "pending"
    pct = 0.0
    message = ""
    upload_id = None
    result = None
    error = None
    updated_at = None

    if progress:
        status = progress.get("status") or progress.get("task_state") or "running"
        if progress.get("progress") is not None:
            pct = float(progress["progress"])
        message = progress.get("message") or ""
        error = progress.get("error")
        extra = progress.get("extra") or {}
        if pct >= 100 and not error and extra and "packet_count" in extra:
            status = "completed"
            result = extra
        if error:
            status = "failed"
        updated_at = progress.get("updated_at")
        if extra and "upload_id" in extra:
            upload_id = extra["upload_id"]

    if status in ("pending", "running") and RQ_AVAILABLE:
        try:
            from rq.job import Job
            from task_queue import get_redis_conn
            r = get_redis_conn()
            job = Job.fetch(task_id, connection=r)
            status_map = {
                "queued": "pending",
                "started": "running",
                "deferred": "pending",
                "scheduled": "pending",
                "finished": "completed",
                "failed": "failed",
                "canceled": "failed",
                "stopped": "failed",
            }
            rq_status = job.get_status()
            if status in ("pending", "running"):
                new_s = status_map.get(rq_status, status)
                if status != "completed" or new_s != status:
                    status = new_s
            if rq_status == "finished" and result is None and job.result:
                result = job.result
                status = "completed"
            if rq_status == "failed" and not error:
                try:
                    exc = job.exc_info
                    if exc:
                        error = exc.splitlines()[-1] if isinstance(exc, str) else str(exc)
                        status = "failed"
                except Exception:
                    pass
            if upload_id is None and result and "upload_id" in result:
                upload_id = result["upload_id"]
        except Exception:
            pass

    return TaskStatusResponse(
        task_id=task_id,
        status=status,
        progress=min(100.0, max(0.0, pct)),
        message=message,
        upload_id=upload_id,
        result=result,
        error=error,
        updated_at=updated_at,
    )


@app.post("/api/tasks/{task_id}/cancel")
def cancel_task(task_id: str, db: sqlite3.Connection = Depends(get_db)):
    canceled = False
    message = ""
    if task_id in _sync_parse_threads:
        t = _sync_parse_threads.get(task_id)
        if t and t.is_alive():
            message = "线程池任务取消请求已记录（将在下一检查点终止）"
            canceled = True
    if RQ_AVAILABLE:
        try:
            from rq.job import Job
            from rq.command import send_stop_job_command
            from task_queue import get_redis_conn
            r = get_redis_conn()
            job = Job.fetch(task_id, connection=r)
            job.cancel()
            try:
                send_stop_job_command(r, task_id)
            except Exception:
                pass
            canceled = True
            message = "RQ 任务已取消"
        except Exception as e:
            if not canceled:
                raise HTTPException(status_code=404, detail=f"任务不存在或无法取消: {e}")
    try:
        c = db.cursor()
        c.execute("""
            INSERT INTO tasks (id, status, message, updated_at)
            VALUES (?, 'failed', ?, ?)
            ON CONFLICT(id) DO UPDATE SET status='failed', message=excluded.message, updated_at=excluded.updated_at
        """, (task_id, message or "任务已取消", time.time()))
        db.commit()
    except Exception:
        pass
    return {"task_id": task_id, "canceled": canceled, "message": message or "任务取消请求已提交"}


@app.get("/api/uploads", response_model=List[UploadInfo])
def list_uploads(db: sqlite3.Connection = Depends(get_db)):
    c = db.cursor()
    c.execute("""
        SELECT id, filename, uploaded_at, packet_count, status, min_timestamp, max_timestamp
        FROM uploads ORDER BY id DESC
    """)
    rows = c.fetchall()
    return [
        UploadInfo(
            id=r["id"],
            filename=r["filename"],
            uploaded_at=r["uploaded_at"],
            packet_count=r["packet_count"],
            status=r["status"],
            min_timestamp=r["min_timestamp"],
            max_timestamp=r["max_timestamp"],
        )
        for r in rows
    ]


@app.get("/api/uploads/{upload_id}", response_model=UploadInfo)
def get_upload(upload_id: int, db: sqlite3.Connection = Depends(get_db)):
    c = db.cursor()
    c.execute("""
        SELECT id, filename, uploaded_at, packet_count, status, min_timestamp, max_timestamp
        FROM uploads WHERE id=?
    """, (upload_id,))
    r = c.fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="Upload not found")
    return UploadInfo(
        id=r["id"],
        filename=r["filename"],
        uploaded_at=r["uploaded_at"],
        packet_count=r["packet_count"],
        status=r["status"],
        min_timestamp=r["min_timestamp"],
        max_timestamp=r["max_timestamp"],
    )


@app.get("/api/time-range")
def get_time_range(
    upload_id: int,
    filters: Optional[str] = Query(None, description="JSON 字符串数组，格式见 /filters 文档"),
    db: sqlite3.Connection = Depends(get_db),
):
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, PACKET_ALLOWED_FIELDS)
    c = db.cursor()
    params: List[Any] = [upload_id] + extra_params
    where = f"p.upload_id = ?{extra_sql}"
    sql = f"""
        SELECT MIN(p.timestamp) as min_ts, MAX(p.timestamp) as max_ts, COUNT(*) as cnt
        FROM packets p WHERE {where}
    """
    c.execute(sql, params)
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
    filters: Optional[str] = Query(None, description="JSON 字符串数组"),
    db: sqlite3.Connection = Depends(get_db),
):
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, PACKET_ALLOWED_FIELDS)

    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "p.upload_id = ?"
    if start_ts is not None:
        where += " AND p.timestamp >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND p.timestamp <= ?"
        params.append(end_ts)
    params += extra_params
    where += extra_sql

    c.execute(f"SELECT MIN(p.timestamp) as m FROM packets p WHERE {where}", params)
    r = c.fetchone()
    if not r or r["m"] is None:
        return {"buckets": [], "window_sec": window_sec}

    base = r["m"]

    sql = f"""
        SELECT
            CAST((p.timestamp - ?) / ? AS INTEGER) as bucket_idx,
            p.protocol,
            COUNT(*) as packet_count,
            SUM(p.length) as total_bytes
        FROM packets p
        WHERE {where}
        GROUP BY bucket_idx, p.protocol
        ORDER BY bucket_idx, p.protocol
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
    filters: Optional[str] = Query(None, description="JSON 字符串数组"),
    db: sqlite3.Connection = Depends(get_db),
):
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, PACKET_ALLOWED_FIELDS)

    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "p.upload_id = ?"
    if start_ts is not None:
        where += " AND p.timestamp >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND p.timestamp <= ?"
        params.append(end_ts)
    params += extra_params
    where += extra_sql

    c.execute(f"""
        SELECT
            COALESCE(p.protocol, 'OTHER') as protocol,
            COUNT(*) as packet_count,
            SUM(p.length) as total_bytes
        FROM packets p
        WHERE {where}
        GROUP BY p.protocol
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
    filters: Optional[str] = Query(None, description="JSON 字符串数组"),
    db: sqlite3.Connection = Depends(get_db),
):
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, PACKET_ALLOWED_FIELDS)

    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "p.upload_id = ?"
    if start_ts is not None:
        where += " AND p.timestamp >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND p.timestamp <= ?"
        params.append(end_ts)
    params += extra_params
    where += extra_sql

    c.execute(f"""
        SELECT
            p.src_ip,
            p.dst_ip,
            p.protocol,
            COUNT(*) as packet_count,
            SUM(p.length) as total_bytes
        FROM packets p
        WHERE {where}
          AND p.src_ip IS NOT NULL
          AND p.dst_ip IS NOT NULL
        GROUP BY p.src_ip, p.dst_ip, p.protocol
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
    filters: Optional[str] = Query(None, description="JSON 字符串数组"),
    db: sqlite3.Connection = Depends(get_db),
):
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, SESSION_ALLOWED_FIELDS)

    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "s.upload_id = ?"
    if start_ts is not None:
        where += " AND s.end_time >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND s.start_time <= ?"
        params.append(end_ts)
    if protocol:
        where += " AND s.protocol = ?"
        params.append(protocol)
    params += extra_params
    where += extra_sql

    c.execute(f"""
        SELECT s.*
        FROM sessions s
        WHERE {where}
        ORDER BY s.total_bytes DESC
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
    filters: Optional[str] = Query(None, description="JSON 字符串数组"),
    db: sqlite3.Connection = Depends(get_db),
):
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, PACKET_ALLOWED_FIELDS)

    c = db.cursor()
    params: List[Any] = [session_id]
    where = "p.session_id = ?"
    if upload_id is not None:
        where += " AND p.upload_id = ?"
        params.append(upload_id)
    params += extra_params
    where += extra_sql

    c.execute(f"""
        SELECT p.*
        FROM packets p
        WHERE {where}
        ORDER BY p.timestamp ASC
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
    filters: Optional[str] = Query(None, description="JSON 字符串数组"),
    db: sqlite3.Connection = Depends(get_db),
):
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, SESSION_ALLOWED_FIELDS)

    start = timestamp - tolerance_sec
    end = timestamp + tolerance_sec
    c = db.cursor()
    params: List[Any] = [upload_id, start, end]
    where = "s.upload_id = ? AND s.start_time <= ? AND s.end_time >= ?"
    if protocol:
        where += " AND s.protocol = ?"
        params.append(protocol)
    params += extra_params
    where += extra_sql

    c.execute(f"""
        SELECT s.*
        FROM sessions s
        WHERE {where}
        ORDER BY s.total_bytes DESC
        LIMIT ?
    """, params + [top_n])
    rows = c.fetchall()
    return {
        "timestamp": timestamp,
        "tolerance_sec": tolerance_sec,
        "sessions": [dict(r) for r in rows],
    }


@app.get("/api/anomaly/ips")
def anomaly_ips(
    upload_id: int,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    window_sec: float = Query(5.0, ge=0.1, description="统计窗口大小（秒），用于基线计算"),
    sigma: float = Query(3.0, ge=1.0, le=10.0, description="异常阈值标准差倍数"),
    direction: str = Query("both", description="uplink / downlink / both"),
    top_k: int = Query(50, ge=1, le=500, description="返回最多多少个异常点"),
    filters: Optional[str] = Query(None, description="JSON 字符串数组（在计算前过滤 packets）"),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    统计学异常检测：
    1. 按时间窗口（默认5s）统计每个IP的上下行总字节数
    2. 计算每个IP的全局基线：均值(μ)和标准差(σ)
    3. 某窗口字节数 > μ + sigma * σ 判定为异常
    4. 返回异常点列表（含具体窗口时刻、IP、实际值、基线）
    """
    import math
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, PACKET_ALLOWED_FIELDS)

    c = db.cursor()

    # Step 1: 确定时间基准
    base_params: List[Any] = [upload_id]
    base_where = "p.upload_id = ?"
    if start_ts is not None:
        base_where += " AND p.timestamp >= ?"
        base_params.append(start_ts)
    if end_ts is not None:
        base_where += " AND p.timestamp <= ?"
        base_params.append(end_ts)
    base_params += extra_params
    base_where += extra_sql

    c.execute(f"SELECT MIN(p.timestamp) as mn, MAX(p.timestamp) as mx FROM packets p WHERE {base_where}", base_params)
    r0 = c.fetchone()
    if not r0 or r0["mn"] is None:
        return {"baselines": [], "anomalies": [], "window_sec": window_sec, "sigma": sigma}

    base_ts = r0["mn"]

    # Step 2: 构建每个窗口每个 IP 的上行/下行字节统计
    # 上行 (uplink) = 以该 IP 为 src_ip 发出的流量
    # 下行 (downlink) = 以该 IP 为 dst_ip 接收的流量
    directions_sql = []
    union_params: List[Any] = []

    if direction in ("uplink", "both"):
        directions_sql.append(f"""
            SELECT
                CAST((p.timestamp - ?) / ? AS INTEGER) as bucket,
                p.src_ip as ip,
                'uplink' as direction,
                SUM(p.length) as bytes
            FROM packets p
            WHERE {base_where} AND p.src_ip IS NOT NULL
            GROUP BY bucket, p.src_ip
        """)
        union_params.extend([base_ts, window_sec] + base_params)
    if direction in ("downlink", "both"):
        directions_sql.append(f"""
            SELECT
                CAST((p.timestamp - ?) / ? AS INTEGER) as bucket,
                p.dst_ip as ip,
                'downlink' as direction,
                SUM(p.length) as bytes
            FROM packets p
            WHERE {base_where} AND p.dst_ip IS NOT NULL
            GROUP BY bucket, p.dst_ip
        """)
        union_params.extend([base_ts, window_sec] + base_params)

    if not directions_sql:
        return {"baselines": [], "anomalies": [], "window_sec": window_sec, "sigma": sigma}

    union_sql = " UNION ALL ".join(directions_sql)

    c.execute(f"""
        CREATE TEMP TABLE IF NOT EXISTS _ip_stats AS
        {union_sql}
    """, union_params)

    # Step 3: 按 (ip, direction) 计算统计量：样本数N、均值μ、方差σ²、标准差σ
    c.execute("""
        SELECT
            ip,
            direction,
            COUNT(*) as n,
            AVG(bytes) as mean,
            CASE WHEN COUNT(*) > 1
                 THEN MAX(0.0, (SUM(bytes * bytes) - COUNT(*) * AVG(bytes) * AVG(bytes)) / (COUNT(*) - 1))
                 ELSE 0.0 END as var,
            MIN(bytes) as min_b,
            MAX(bytes) as max_b,
            SUM(bytes) as total_b
        FROM _ip_stats
        GROUP BY ip, direction
        HAVING COUNT(*) >= 3
    """)
    baselines_raw = c.fetchall()

    baselines = []
    ip_baseline_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for b in baselines_raw:
        std = math.sqrt(b["var"]) if b["var"] and b["var"] > 0 else 0.0
        entry = {
            "ip": b["ip"],
            "direction": b["direction"],
            "n_windows": b["n"],
            "mean": float(b["mean"] or 0),
            "std": std,
            "min": float(b["min_b"] or 0),
            "max": float(b["max_b"] or 0),
            "total": float(b["total_b"] or 0),
            "threshold": float(b["mean"] or 0) + sigma * std,
        }
        baselines.append(entry)
        ip_baseline_map[(entry["ip"], entry["direction"])] = entry

    # Step 4: 找出所有超过阈值 μ + sigma * σ 的异常点
    anomaly_results = []
    if ip_baseline_map:
        # 逐窗口计算，避免一次性加载
        c.execute("SELECT * FROM _ip_stats")
        for s in c.fetchall():
            key = (s["ip"], s["direction"])
            bl = ip_baseline_map.get(key)
            if not bl:
                continue
            bytes_val = float(s["bytes"])
            if bytes_val > bl["threshold"] and bl["std"] > 0:
                z = (bytes_val - bl["mean"]) / bl["std"] if bl["std"] > 0 else 0
                anomaly_results.append({
                    "ip": s["ip"],
                    "direction": s["direction"],
                    "bucket_idx": int(s["bucket"]),
                    "window_start": float(base_ts + s["bucket"] * window_sec),
                    "window_mid": float(base_ts + (s["bucket"] + 0.5) * window_sec),
                    "window_end": float(base_ts + (s["bucket"] + 1) * window_sec),
                    "bytes": bytes_val,
                    "mean": bl["mean"],
                    "std": bl["std"],
                    "threshold": bl["threshold"],
                    "sigma_over": float(z),
                    "ratio_vs_mean": round(bytes_val / bl["mean"], 2) if bl["mean"] > 0 else None,
                })

    anomaly_results.sort(key=lambda x: x["sigma_over"], reverse=True)
    anomaly_results = anomaly_results[:top_k]

    c.execute("DROP TABLE IF EXISTS _ip_stats")

    baselines.sort(key=lambda x: x["total"], reverse=True)

    return {
        "window_sec": window_sec,
        "sigma": sigma,
        "time_range": {"start": r0["mn"], "end": r0["mx"], "base": base_ts},
        "baselines": baselines[:1000],
        "anomalies": anomaly_results,
    }


@app.get("/api/ip/sessions")
def ip_sessions(
    upload_id: int,
    ip: str = Query(..., description="要查询的 IP 地址"),
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    direction: str = Query("both", description="as_src / as_dst / both"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    filters: Optional[str] = Query(None, description="JSON 字符串数组"),
    db: sqlite3.Connection = Depends(get_db),
):
    """查询指定 IP 参与的所有会话列表（含每个方向流量统计），用于异常点点击下钻。"""
    filter_arr = parse_filters_from_query(filters)
    extra_sql, extra_params = parse_filters(filter_arr, SESSION_ALLOWED_FIELDS)

    c = db.cursor()
    params: List[Any] = [upload_id]
    where = "s.upload_id = ?"

    if direction == "as_src":
        where += " AND s.src_ip = ?"
        params.append(ip)
    elif direction == "as_dst":
        where += " AND s.dst_ip = ?"
        params.append(ip)
    else:
        where += " AND (s.src_ip = ? OR s.dst_ip = ?)"
        params.extend([ip, ip])

    if start_ts is not None:
        where += " AND s.end_time >= ?"
        params.append(start_ts)
    if end_ts is not None:
        where += " AND s.start_time <= ?"
        params.append(end_ts)
    params += extra_params
    where += extra_sql

    c.execute(f"""
        SELECT s.*,
            CASE WHEN s.src_ip = ? THEN s.total_bytes ELSE 0 END as sent_bytes,
            CASE WHEN s.dst_ip = ? THEN s.total_bytes ELSE 0 END as recv_bytes
        FROM sessions s
        WHERE {where}
        ORDER BY s.total_bytes DESC
        LIMIT ? OFFSET ?
    """, [ip, ip] + params + [limit, offset])
    rows = c.fetchall()

    cnt_sql = f"SELECT COUNT(*) as cnt FROM sessions s WHERE {where}"
    c.execute(cnt_sql, params)
    cnt_r = c.fetchone()

    stat_sql = f"""
        SELECT
            COUNT(*) as sessions,
            COALESCE(SUM(CASE WHEN s.src_ip = ? THEN s.total_bytes ELSE 0 END), 0) as total_sent,
            COALESCE(SUM(CASE WHEN s.dst_ip = ? THEN s.total_bytes ELSE 0 END), 0) as total_recv,
            COALESCE(SUM(s.packet_count), 0) as total_packets
        FROM sessions s
        WHERE {where}
    """
    c.execute(stat_sql, [ip, ip] + params)
    stat_r = c.fetchone()

    return {
        "ip": ip,
        "direction": direction,
        "stats": {
            "total_sessions": stat_r["sessions"] if stat_r else 0,
            "total_sent": stat_r["total_sent"] if stat_r else 0,
            "total_recv": stat_r["total_recv"] if stat_r else 0,
            "total_bytes": (stat_r["total_sent"] or 0) + (stat_r["total_recv"] or 0),
            "total_packets": stat_r["total_packets"] or 0,
        },
        "total": cnt_r["cnt"] if cnt_r else 0,
        "sessions": [dict(r) for r in rows],
    }


@app.get("/api/filters/schema")
def filters_schema():
    """返回可用的过滤字段/操作符，供前端生成过滤面板。"""
    from filters import ALLOWED_OPS
    packet_fields = []
    for name, cfg in PACKET_ALLOWED_FIELDS.items():
        packet_fields.append({
            "field": name,
            "type": cfg["type"],
            "sql_table": cfg.get("table", ""),
            "special": cfg.get("special"),
            "label": {
                "timestamp": "时间戳 (s)",
                "src_ip": "源 IP",
                "dst_ip": "目的 IP",
                "ip": "任一侧 IP",
                "src_port": "源端口",
                "dst_port": "目的端口",
                "port": "任一侧端口",
                "protocol": "协议",
                "length": "包长度 (B)",
                "payload_size": "载荷大小 (B)",
                "tcp_flags": "TCP Flags",
                "session_id": "会话 ID",
                "start_time": "会话开始时间",
                "end_time": "会话结束时间",
                "duration": "会话持续时间",
                "packet_count": "会话包数",
                "total_bytes": "会话总字节",
            }.get(name, name),
        })
    ops = [
        {"op": "==", "label": "等于 (==", "types": ["number", "string"]},
        {"op": "!=", "label": "不等于 (!=)", "types": ["number", "string"]},
        {"op": ">", "label": "大于 (>)", "types": ["number"]},
        {"op": ">=", "label": "大于等于 (>=)", "types": ["number"]},
        {"op": "<", "label": "小于 (<)", "types": ["number"]},
        {"op": "<=", "label": "小于等于 (<=)", "types": ["number"]},
        {"op": "contains", "label": "包含 (LIKE %x%)", "types": ["string"]},
        {"op": "not_contains", "label": "不包含", "types": ["string"]},
        {"op": "startswith", "label": "开头是", "types": ["string"]},
        {"op": "endswith", "label": "结尾是", "types": ["string"]},
        {"op": "in", "label": "值之一 (逗号分隔)", "types": ["number", "string"]},
        {"op": "not_in", "label": "不在其中 (逗号分隔)", "types": ["number", "string"]},
        {"op": "has_flag", "label": "包含 TCP Flag", "types": ["string"]},
        {"op": "regex", "label": "正则匹配 (REGEXP)", "types": ["string"]},
    ]
    return {"packet_fields": packet_fields, "ops": ops}


@app.get("/api/health")
def health():
    from parser import find_tshark, tshark_version_ok, SCAPY_AVAILABLE, PANDAS_AVAILABLE
    info = {
        "status": "ok",
        "db_exists": os.path.exists(DB_PATH),
        "parsers": {},
        "queue": {},
    }
    tshark_path = find_tshark()
    info["parsers"]["tshark"] = {
        "available": bool(tshark_path and tshark_version_ok(tshark_path)),
        "path": tshark_path,
    }
    info["parsers"]["scapy"] = {"available": SCAPY_AVAILABLE}
    info["parsers"]["pandas"] = {"available": PANDAS_AVAILABLE}
    try:
        q = get_queue()
        info["queue"]["rq_available"] = q is not None
        if q is not None:
            info["queue"]["queued_jobs"] = q.count
            try:
                from task_queue import get_redis_conn
                r = get_redis_conn()
                info["queue"]["redis_connected"] = bool(r.ping())
            except Exception:
                info["queue"]["redis_connected"] = False
    except Exception as e:
        info["queue"] = {"rq_available": False, "error": str(e)}
    return info
