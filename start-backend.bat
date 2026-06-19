@echo off
chcp 65001 >nul
echo ============================================
echo    启动后端服务 (FastAPI - port 8000)
echo ============================================
cd /d "%~dp0backend"

echo [1/2] 检查 Python 依赖...
if not exist "venv" (
    echo 创建虚拟环境...
    python -m venv venv
)
call venv\Scripts\activate.bat
pip install -r requirements.txt

echo.
echo [2/2] 启动 FastAPI 服务...
echo 服务地址: http://localhost:8000
echo API 文档: http://localhost:8000/docs
echo.
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
