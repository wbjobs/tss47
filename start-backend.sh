#!/bin/bash
echo "============================================"
echo "   启动后端服务 (FastAPI - port 8000)"
echo "============================================"
cd "$(dirname "$0")/backend"

echo "[1/2] 检查 Python 依赖..."
if [ ! -d "venv" ]; then
    echo "创建虚拟环境..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt

echo
echo "[2/2] 启动 FastAPI 服务..."
echo "服务地址: http://localhost:8000"
echo "API 文档: http://localhost:8000/docs"
echo
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
