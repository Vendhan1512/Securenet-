@echo off
REM Production LAN Security System Startup Script for Windows
REM This script starts the security system in production mode

echo 🚀 Starting LAN Security System - Production Mode
echo ==================================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Error: This script must be run as Administrator for network monitoring
    echo    Please run as Administrator
    pause
    exit /b 1
)

REM Set production environment variables
set PRODUCTION_MODE=true
set LOG_LEVEL=WARNING
set SIEM_API_KEY=your-siem-api-key-here

REM Create log directory if it doesn't exist
if not exist "logs\production" mkdir logs\production

REM Get network interface (default to first available)
set INTERFACE=%1
if "%INTERFACE%"=="" set INTERFACE=Ethernet

echo ✅ Using network interface: %INTERFACE%
echo ✅ Production environment configured
echo ✅ Starting security monitoring...

REM Start the production system
python production_main.py --daemon --interface %INTERFACE% --config production_config.yaml --log-level WARNING

if %errorLevel% neq 0 (
    echo ❌ Failed to start production system
    pause
    exit /b 1
)

echo 🛡️  LAN Security System is now protecting your network!
echo 📊 Monitor logs: type logs\production\production_security.log
echo 🔍 Check status: python production_main.py --status --interface %INTERFACE%
pause