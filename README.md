# 网络流量可视化分析器

基于 **Python FastAPI + Scapy + SQLite** 后端与 **Node.js + Vite + D3.js** 前端的网络流量分析可视化系统。

## 功能特性

- 📁 **文件上传**：支持 `.pcap` / `.pcapng` 格式
- 🔍 **逐包解析**：提取五元组（源IP、目的IP、源端口、目的端口、协议）+ TCP flags + 会话分组
- 📊 **时间窗口聚合**：按 0.1s / 0.5s / 1s / 2s / 5s / 10s 统计流量包数与字节数
- 🌊 **流量河流图 (Streamgraph)**：D3.js 实现的协议级堆叠可视化，实时重渲染
- 🕒 **双滑块时间轴**：拖动筛选任意时间范围
- 🥧 **协议占比**：环形图展示包数/字节占比
- 🏆 **IP对排行**：Top 15 IP 通信量排名
- 🎯 **交互式下钻**：
  - 点击河流图波峰 → 查看该时刻附近活跃的 TCP/UDP 会话列表
  - 点击会话详情 → 查看该会话的逐包信息（时间戳、Flags、载荷等）

## 项目结构

```
tss47/
├── backend/                    # FastAPI 后端
│   ├── main.py                 # API 入口（上传、查询、下钻）
│   ├── parser.py               # Scapy 逐包解析 + 会话聚合
│   ├── database.py             # SQLite 初始化与连接
│   ├── generate_sample_pcap.py # 测试数据生成脚本
│   ├── requirements.txt
│   ├── uploads/                # 上传文件临时存储
│   └── traffic.db              # SQLite 数据库（运行后自动生成）
├── frontend/                   # Vite + D3.js 前端
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   └── src/
│       ├── main.js             # 核心逻辑（API调用 + D3可视化 + 交互）
│       └── styles.css          # 暗色主题样式
├── start-backend.bat / .sh     # 后端一键启动脚本
└── start-frontend.bat / .sh    # 前端一键启动脚本
```

## 快速开始

### 1. 启动后端

**Windows:**
```bat
start-backend.bat
```

**Linux/Mac:**
```bash
chmod +x start-backend.sh
./start-backend.sh
```

或手动执行：
```bash
cd backend
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

后端地址: http://localhost:8000
API 文档 (Swagger): http://localhost:8000/docs

### 2. 启动前端（新开一个终端）

**Windows:**
```bat
start-frontend.bat
```

**Linux/Mac:**
```bash
chmod +x start-frontend.sh
./start-frontend.sh
```

或手动执行：
```bash
cd frontend
npm install
npm run dev
```

前端地址: http://localhost:5173

### 3. 生成测试数据（可选）

如果手头没有 pcap 文件，可以运行测试数据生成脚本：

```bash
cd backend
# 确保已激活 venv 并安装 scapy
python generate_sample_pcap.py
```

脚本会生成两个文件：
- `backend/test_data/sample_traffic.pcap` (2000 包)
- `backend/test_data/sample_traffic_large.pcap` (8000 包)

## API 接口列表

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/upload` | 上传 pcap/pcapng 文件，触发解析入库 |
| GET | `/api/uploads` | 获取所有上传记录 |
| GET | `/api/uploads/{id}` | 获取单个上传记录 |
| GET | `/api/time-range` | 获取数据集时间范围与包数 |
| GET | `/api/traffic/time-window` | 按时间窗口聚合流量（河流图数据） |
| GET | `/api/protocol/distribution` | 协议占比统计 |
| GET | `/api/ip-pairs/ranking` | IP 对通信量排行 |
| GET | `/api/sessions/list` | 会话列表（支持时间/协议过滤） |
| GET | `/api/sessions/at-time` | 某时刻附近的活跃会话（下钻入口） |
| GET | `/api/sessions/{id}/packets` | 指定会话的逐包详情 |
| GET | `/api/health` | 健康检查 |

## 使用流程

1. 打开 http://localhost:5173
2. 点击右上角 **📁 上传 pcap / pcapng 文件**，或在下拉框中选择历史数据集
3. 解析完成后：
   - 使用顶部 **时间窗口 / 指标** 切换聚合粒度与统计维度
   - 拖动 **时间范围双滑块** 截取任意时段
   - 在河流图上 **悬停** 查看协议级详情
   - 在河流图上 **点击任意位置** 下钻查看该时刻的活跃会话
   - 点击会话行的 **「详情」** 按钮查看逐包信息

## 技术要点

### 后端
- **Scapy**：`rdpcap()` 逐包读取，按 IPv4/IPv6 → TCP/UDP/ICMP 层级提取
- **SQLite**：批量插入（5000/批）+ 会话聚合字典，兼顾解析性能
- **会话 ID 设计**：`PROTO-ip1-ip2-port1-port2`（IP与端口均排序后拼接，保证双向流同属一会话）

### 前端
- **Streamgraph 算法**：D3 `stackOffsetWiggle` + `stackOrderInsideOut` 实现美观的河流布局
- **双滑块交互**：双层 range input 叠加 + 动态位置计算
- **下钻交互**：点击位置通过 `d3.bisector` 定位到最近的时间桶，调用会话查询 API
