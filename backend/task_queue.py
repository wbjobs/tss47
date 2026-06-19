import os
import time
import json
import traceback
from typing import Optional, Dict, Any
from datetime import datetime

try:
    import redis
    from rq import Queue, Worker, get_current_job
    from rq.job import Job, JobStatus
    RQ_AVAILABLE = True
except ImportError:
    RQ_AVAILABLE = False

from database import get_db_sync, init_db


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
TASK_TIMEOUT = 3600


def get_redis_conn():
    if not RQ_AVAILABLE:
        raise RuntimeError("Redis/RQ 未安装，请先 pip install redis rq 并启动 Redis 服务")
    return redis.Redis.from_url(REDIS_URL)


def get_queue(name: str = "default") -> Optional["Queue"]:
    if not RQ_AVAILABLE:
        return None
    try:
        r = get_redis_conn()
        r.ping()
        return Queue(name=name, connection=r, default_timeout=TASK_TIMEOUT)
    except Exception:
        return None


def _task_progress_key(task_id: str) -> str:
    return f"task:progress:{task_id}"


def update_task_progress(task_id: str, progress: float, message: str = "", extra: Optional[Dict[str, Any]] = None):
    payload = {
        "task_id": task_id,
        "progress": max(0.0, min(100.0, float(progress))),
        "message": message,
        "updated_at": time.time(),
        "extra": extra or {},
    }
    try:
        r = get_redis_conn()
        r.setex(_task_progress_key(task_id), 86400, json.dumps(payload))
    except Exception:
        pass
    try:
        with get_db_sync() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO tasks (id, status, progress, message, updated_at, result_data)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    progress=excluded.progress,
                    message=excluded.message,
                    updated_at=excluded.updated_at
            """, (
                task_id,
                "running",
                payload["progress"],
                message,
                payload["updated_at"],
                json.dumps(payload["extra"]) if payload["extra"] else None,
            ))
            conn.commit()
    except Exception:
        pass


def get_task_progress(task_id: str) -> Optional[Dict[str, Any]]:
    try:
        r = get_redis_conn()
        raw = r.get(_task_progress_key(task_id))
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    try:
        with get_db_sync() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM tasks WHERE id=?", (task_id,))
            row = c.fetchone()
            if row:
                return {
                    "task_id": row["id"],
                    "status": row["status"],
                    "progress": row["progress"],
                    "message": row["message"] or "",
                    "updated_at": row["updated_at"],
                    "extra": json.loads(row["result_data"]) if row["result_data"] else {},
                    "error": row["error_message"],
                }
    except Exception:
        pass
    return None


def mark_task_failed(task_id: str, error_msg: str):
    try:
        payload = {
            "task_id": task_id,
            "progress": 0,
            "message": f"失败: {error_msg}",
            "updated_at": time.time(),
            "error": error_msg,
        }
        r = get_redis_conn()
        r.setex(_task_progress_key(task_id), 86400, json.dumps(payload))
    except Exception:
        pass
    try:
        with get_db_sync() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO tasks (id, status, progress, message, error_message, updated_at)
                VALUES (?, 'failed', 0, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status='failed',
                    progress=0,
                    message=excluded.message,
                    error_message=excluded.error_message,
                    updated_at=excluded.updated_at
            """, (task_id, f"失败: {error_msg}", error_msg, time.time()))
            conn.commit()
    except Exception:
        pass


def mark_task_completed(task_id: str, message: str, result: Dict[str, Any]):
    payload = {
        "task_id": task_id,
        "progress": 100,
        "message": message,
        "updated_at": time.time(),
        "extra": result,
    }
    try:
        r = get_redis_conn()
        r.setex(_task_progress_key(task_id), 86400, json.dumps(payload))
    except Exception:
        pass
    try:
        with get_db_sync() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO tasks (id, status, progress, message, updated_at, result_data)
                VALUES (?, 'completed', 100, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status='completed',
                    progress=100,
                    message=excluded.message,
                    updated_at=excluded.updated_at,
                    result_data=excluded.result_data
            """, (task_id, message, time.time(), json.dumps(result)))
            conn.commit()
    except Exception:
        pass


def enqueue_parse_task(file_path: str, upload_id: int, filename: str) -> Dict[str, Any]:
    init_db()
    task_id = f"parse-{upload_id}-{int(time.time() * 1000)}"

    q = get_queue()
    if q is None:
        return {
            "mode": "sync_fallback",
            "task_id": task_id,
            "note": "Redis 未连接，将使用同步线程池（FastAPI run_in_executor）执行",
        }

    from parser import parse_pcap_file_async
    job = q.enqueue(
        parse_pcap_file_async,
        args=(file_path, upload_id, filename, task_id),
        job_id=task_id,
        job_timeout=TASK_TIMEOUT,
        result_ttl=86400,
    )
    return {
        "mode": "rq",
        "task_id": job.id,
    }


def run_worker(queue_name: str = "default"):
    if not RQ_AVAILABLE:
        print("❌ rq / redis 未安装，无法启动 worker")
        return
    try:
        r = get_redis_conn()
        print(f"✅ Redis 已连接: {REDIS_URL}")
    except Exception as e:
        print(f"❌ 无法连接 Redis: {e}")
        print("   请先启动 Redis 服务，例如: redis-server")
        return
    init_db()
    print(f"🚀 启动 RQ worker，队列: {queue_name}")
    worker = Worker([queue_name], connection=r)
    worker.work()


if __name__ == "__main__":
    import sys
    qname = sys.argv[1] if len(sys.argv) > 1 else "default"
    run_worker(qname)
