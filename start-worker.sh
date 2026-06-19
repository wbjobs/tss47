#!/bin/bash
echo "============================================"
echo "   启动 RQ Worker (解析任务队列)"
echo "============================================"
cd "$(dirname "$0")/backend"

if [ ! -d "venv" ]; then
    echo "创建虚拟环境..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt

echo
echo "============================================"
echo " 提示："
echo "  1. 请先启动 Redis 服务：redis-server"
echo "  2. 确认 tshark 已安装 (Wireshark CLI)"
echo "     Ubuntu/Debian: sudo apt install tshark"
echo "     macOS: brew install wireshark"
echo "============================================"
echo

python task_queue.py default
