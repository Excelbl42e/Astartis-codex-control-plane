@echo off
chcp 65001 >nul
echo ==========================================
echo   Astartis v3.0 Dashboard Starter
echo ==========================================
echo.

REM Find the exe — prefer the one copied to dashboard/, fallback to build dir
set "EXE_PATH=demo_dashboard_data.exe"
if not exist "%EXE_PATH%" (
    set "EXE_PATH=..\build\Release\demo_dashboard_data.exe"
)
if not exist "%EXE_PATH%" (
    set "EXE_PATH=..\build\Release\Release\demo_dashboard_data.exe"
)

if not exist "%EXE_PATH%" (
    echo ERROR: demo_dashboard_data.exe not found.
    echo Please build the project first:
    echo   cmake --build . --config Release --target demo_dashboard_data
    pause
    exit /b 1
)

echo Starting Astartis Dashboard Server...
echo Executable: %EXE_PATH%
echo.
echo The dashboard will open automatically.
echo Press Ctrl+C here to stop the server.
echo.

REM Start the server in this directory (dashboard/) so output path resolves correctly
cd /d "%~dp0"
start "Astartis Dashboard Server" /MIN "%EXE_PATH%" .

REM Give it a moment to start
timeout /t 3 /nobreak >nul

REM Open browser
start http://127.0.0.1:9876/

echo.
echo Dashboard opened at: http://127.0.0.1:9876/
echo.
pause
