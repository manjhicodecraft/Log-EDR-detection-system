@echo off
setlocal
cd /d "%~dp0"

title Trinetra Sentinel Desktop
echo.
echo  ==========================================
echo        TRINETRA SENTINEL DESKTOP
echo  ==========================================
echo.

where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js/npm is not installed or not available in PATH.
    echo Install Node.js 18 or newer, then run this file again.
    pause
    exit /b 1
)

pushd frontend
if not exist "node_modules" (
    echo [SETUP] Installing frontend and Electron dependencies...
    call npm install
    if errorlevel 1 (
        popd
        goto :failed
    )
)

echo [START] Launching Trinetra Sentinel desktop app...
call npm run electron
if errorlevel 1 (
    popd
    goto :failed
)
popd
exit /b 0

:failed
echo.
echo [ERROR] Desktop launch failed. Check Python, Node.js, and dependency installation.
pause
exit /b 1
