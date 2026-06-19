@echo off
chcp 65001 >nul
echo ============================================
echo    启动前端服务 (Vite - port 5173)
echo ============================================
cd /d "%~dp0frontend"

echo [1/2] 检查 Node 依赖...
if not exist "node_modules" (
    echo 正在安装依赖...
    call npm install
)

echo.
echo [2/2] 启动 Vite 开发服务...
echo 前端地址: http://localhost:5173
echo.
call npm run dev
pause
