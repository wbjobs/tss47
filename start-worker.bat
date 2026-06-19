@echo off
chcp 65001 >nul
echo ============================================
echo    启动 RQ Worker (解析任务队列)
echo ============================================
cd /d "%~dp0backend"

if not exist "venv" (
    echo 创建虚拟环境...
    python -m venv venv
)
call venv\Scripts\activate.bat
pip install -r requirements.txt

echo.
echo ============================================
echo  提示：
echo   1. 请先启动 Redis 服务
echo      (Windows: 运行 redis-server.exe 或使用 WSL)
echo   2. 确认 tshark 已安装 (Wireshark 命令行工具)
echo ============================================
echo.

python task_queue.py default
pause
