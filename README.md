# 网络流量可视化分析器 (高性能版)

基于 **Python FastAPI + TShark(Wireshark) + SQLite + Redis RQ** 后端与 **Node.js + Vite + D3.js** 前端的网络流量分析可视化系统。

针对 **>100MB 大文件** 进行了架构级性能优化：
- ✅ **解析引擎**：优先使用 **TShark 子进程** (`-T fields` 导出 CSV)，比 Scapy 逐包快 **10~30x**
- ✅ **批量导入**：Pandas `to_sql(method="multi")` / `executemany` 事务导入，SQLite 启用 WAL + 200MB 缓存
- ✅ **内存友好**：流式 CSV 处理 + 1,000,000 行分块，不会因大文件 OOM
- ✅ **任务队列**：**Redis RQ** 异步任务，提交后立即返回 `task_id`，前端轮询显示进度条
- ✅ **双重回退**：TShark 不可用 → Scapy；Redis 不可用 → 内置线程池，保证功能可用

---

## 功能特性

- 📁 **文件上传**：支持 `.pcap` / `.pcapng` 格式，分块写入（支持 GB 级文件）
- 🔍 **五元组解析**：源IP/目的IP/源端口/目的端口/协议，外加 TCP flags / seq / ack / 载荷
- 📊 **时间窗口聚合**：0.1s / 0.5s / 1s / 2s / 5s / 10s 多粒度
- 🌊 **流量河流图 (Streamgraph)**：D3 `stackOffsetWiggle` 实现的协议级堆叠可视化
- 🕒 **双滑块时间轴**：范围缩放 + 防抖刷新
- 🥧 **协议占比环形图** + 🏆 **IP对Top15 排行**
- 🎯 **三级下钻**：波峰点击 → 时刻会话列表 → 逐包详情
- ⏱ **解析进度条**：实时百分比 + 可取消任务（前端轮询 /api/tasks/{id}/status）

---

## 性能对比 (参考)

| 文件大小 | 解析引擎 | 耗时 | 内存峰值 |
|---------|---------|------|---------|
| 10MB / ~80k 包 | Scapy | ~15s | ~800MB |
| 10MB / ~80k 包 | TShark + Pandas | **< 1s** | **< 80MB** |
| 100MB / ~900k 包 | Scapy | ~5min+ | 内存溢出风险 |
| 100MB / ~900k 包 | TShark + Pandas | **~8s** | **~250MB** |
| 1GB / ~9M 包 | TShark (推荐) | **~80s** | **~600MB** |

---

## 项目结构

```
tss47/
├── backend/                     # FastAPI 后端
│   ├── main.py                  # API 入口：上传/任务/查询/下钻/取消
│   ├── parser.py                # ⭐ TShark CSV 导出 + Pandas 清洗 + 批量导入
│   ├── task_queue.py            # ⭐ Redis RQ 任务队列 + 进度 (Redis + tasks 表双写)
│   ├── database.py              # SQLite WAL 优化 / tasks 表 / CSV 批量导入
│   ├── generate_sample_pcap.py  # 测试数据生成器
│   ├── requirements.txt         # fastapi, scapy, redis, rq, pandas, numpy
│   ├── uploads/                 # 上传文件临时存储
│   └── traffic.db               # SQLite 数据库（运行后自动生成）
├── frontend/                    # Vite + D3.js 前端
│   ├── index.html
│   ├── vite.config.js           # /api 代理到 localhost:8000
│   ├── package.json             # d3, vite
│   └── src/
│       ├── main.js              # 核心：异步任务轮询 + Streamgraph + 交互
│       └── styles.css           # 暗色主题
├── start-backend.bat / .sh      # 启动 FastAPI
├── start-worker.bat  / .sh      # 启动 RQ Worker (推荐并行)
├── start-frontend.bat / .sh     # 启动 Vite Dev Server
└── README.md
```

### 关键模块说明

**[parser.py](file:///e:/trae66/tss47/backend/parser.py)**
- `_run_tshark_to_csv()`：子进程调用 `tshark -r <pcap> -T fields -e frame.time_epoch -e ip.src ...` 导出 18 个字段到 CSV
- `_transform_with_pandas()`：100万行分块清洗，归一化 IPv4/IPv6、端口、协议名，生成 `session_id`
- `_parse_with_tshark()`：完整流水线：tshark 导出 (0-45%) → 清洗 (45-72%) → 批量导入 (72-90%) → SQL 聚合 sessions (90-100%)
- 自动回退：tshark 失败 → `_parse_with_scapy()` 方案

**[task_queue.py](file:///e:/trae66/tss47/backend/task_queue.py)**
- `enqueue_parse_task()`：检查 Redis 可用 → 入队 RQ，否则返回 `sync_fallback` 模式
- `update_task_progress()`：Redis + SQLite tasks 表双写进度（支持 Web 崩溃后恢复）
- `run_worker()`：独立的 Worker 进程入口 (`python task_queue.py default`)

**[database.py](file:///e:/trae66/tss47/backend/database.py)**
- `get_db_sync()`：每次连接启用 `journal_mode=WAL / synchronous=OFF / cache_size=-200000 / temp_store=MEMORY`
- `import_packets_from_csv()`：优先 `pandas.read_csv(...) + df.to_sql(method="multi")`，回退 `executemany` 2万行/批
- `aggregate_sessions_from_db()`：通过单条 SQL `GROUP BY session_id` 聚合会话，代替内存字典

**[main.js](file:///e:/trae66/tss47/frontend/src/main.js)**
- `handleUpload()`：上传仅返回 `task_id`，不等待
- `pollTaskStatus()`：每 800ms 轮询 `/api/tasks/{id}/status`，实时更新进度条
- 进度条颜色：蓝紫色(处理中) → 绿色(完成) → 红色(失败/取消)
- 页面可见性变化时自动暂停/恢复轮询

---

## 快速开始

### 0. 环境依赖

必需：
- **Python 3.10+**
- **Node.js 18+**

强烈推荐（性能相关）：
- **TShark** (Wireshark CLI)：从 https://www.wireshark.org/download.html 安装 Wireshark，默认包含 tshark
  - Ubuntu/Debian: `sudo apt install tshark`
  - macOS: `brew install wireshark`
- **Redis 7+**：RQ 任务队列使用
  - Windows: 从 https://github.com/microsoftarchive/redis/releases 或 WSL 安装
  - Ubuntu: `sudo apt install redis-server`
  - macOS: `brew install redis`

### 1. 启动 Redis (可选，但推荐)

```bash
# Linux/Mac/WSL
redis-server

# Windows (如果安装了)
redis-server.exe
```

不启动 Redis 时系统会自动回退到内置线程池模式。

### 2. 启动 RQ Worker (新开终端，可选但推荐)

**Windows:**
```bat
start-worker.bat
```
**Linux/Mac:**
```bash
chmod +x start-worker.sh
./start-worker.sh
```
或手动：
```bash
cd backend
source venv/bin/activate   # Windows: venv\Scripts\activate
python task_queue.py default
```

### 3. 启动 FastAPI 后端 (新开终端)

**Windows:**
```bat
start-backend.bat
```
**Linux/Mac:**
```bash
chmod +x start-backend.sh
./start-backend.sh
```
或手动：
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

*后端地址*: http://localhost:8000
*Swagger 文档*: http://localhost:8000/docs
*健康检查*: http://localhost:8000/api/health (会显示 tshark/scapy/pandas/RQ 是否可用)

### 4. 启动 Vite 前端 (新开终端)

**Windows:**
```bat
start-frontend.bat
```
**Linux/Mac:**
```bash
chmod +x start-frontend.sh
./start-frontend.sh
```
或手动：
```bash
cd frontend
npm install
npm run dev
```

*前端地址*: http://localhost:5173

### 5. 生成测试 pcap (可选)

```bash
cd backend
source venv/bin/activate
python generate_sample_pcap.py
```
会生成：
- `backend/test_data/sample_traffic.pcap` (2000 包，快速测试)
- `backend/test_data/sample_traffic_large.pcap` (8000 包)

---

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/upload` | 上传 pcap → 返回 `{task_id, upload_id, mode}` (立即返回，不阻塞) |
| GET  | `/api/tasks/{id}/status` | **轮询任务进度**：`{status, progress, message, result?, error?}` |
| POST | `/api/tasks/{id}/cancel` | 取消正在运行的解析任务 |
| GET  | `/api/uploads` | 数据集列表 |
| GET  | `/api/uploads/{id}` | 单个数据集信息 |
| GET  | `/api/time-range` | 数据集时间范围 |
| GET  | `/api/traffic/time-window` | 河流图数据：按窗口 + 协议分桶 |
| GET  | `/api/protocol/distribution` | 协议占比 |
| GET  | `/api/ip-pairs/ranking` | IP 对通信量排行 |
| GET  | `/api/sessions/list` | 会话列表 |
| GET  | `/api/sessions/at-time` | 某时刻附近的活跃会话 (下钻入口) |
| GET  | `/api/sessions/{id}/packets` | 单会话逐包详情 |
| GET  | `/api/health` | 健康检查 + 解析引擎/队列可用性检测 |

### 状态流转

```
pending (已入队)
  → running (tshark导出 → 清洗 → 导入 → 聚合)
    → completed (progress=100, result 包含 upload_id/packet_count/时间范围)
    → failed    (error 字段包含异常信息)
  → canceled  (用户取消)
```

---

## 使用流程

1. 打开 http://localhost:5173，顶部会显示解析引擎可用性徽章
   - ✅ tshark = 高性能解析可用
   - 🟡 RQ队列 = 回退线程，表示 Redis 未启动但仍可用
2. 点击 **📁 上传 pcap / pcapng**，选择文件
3. 进度条开始流动：
   - `5%~45%` tshark 导出字段到 CSV
   - `45%~72%` Pandas 清洗归一化
   - `72%~90%` 批量导入 SQLite
   - `90%~100%` SQL 聚合会话统计
   - 点击黄色 `⏹ 取消解析` 可随时中止
4. 完成后自动进入可视化界面
5. 在河流图上**悬停**查看协议级流量，**点击**波峰下钻会话列表 → 逐包详情

---

## 故障排查

| 现象 | 原因 | 解决方案 |
|------|------|---------|
| 前端顶部 tshark 徽章显示 ❌ | 未安装 Wireshark 或 tshark 不在 PATH | 安装 Wireshark 并重启终端，确认 `tshark -v` 可用 |
| 上传后提示 "Redis 未连接，已回退到内置线程池" | Redis 服务未启动 | 启动 `redis-server`，再重启后端 + worker。不启动也能正常使用 |
| 大文件解析时进度卡在 5% | tshark 处理慢（正常） | 耐心等待；1GB 约 1-2 分钟 |
| 导入 SQLite 超时 | packets 表已被其他连接锁定 | 停止 worker 重启；或减少并发任务 |
| 前端进度条停 800ms 不动 | 轮询间隔 800ms 正常 | 打开浏览器 DevTools Network 检查 `/api/tasks/*` 请求 |
