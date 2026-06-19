#!/bin/bash
echo "============================================"
echo "   启动前端服务 (Vite - port 5173)"
echo "============================================"
cd "$(dirname "$0")/frontend"

echo "[1/2] 检查 Node 依赖..."
if [ ! -d "node_modules" ]; then
    echo "正在安装依赖..."
    npm install
fi

echo
echo "[2/2] 启动 Vite 开发服务..."
echo "前端地址: http://localhost:5173"
echo
npm run dev
