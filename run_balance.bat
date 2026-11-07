@echo off
REM BTC Key Hunter v2.0 с проверкой балансов
setlocal
cd /d "%~dp0"

set PYTHON="C:\Users\User3\AppData\Local\Programs\Python\Python312\python.exe"

if not exist %PYTHON% (
    echo ERROR: Python 3.12 не найден!
    pause
    exit /b 1
)

echo.
echo ╔═════════════════════════════════════════╗
echo ║  BTC Key Hunter v2.0 with Balance Check ║
echo ╚═════════════════════════════════════════╝
echo.
echo ВАЖНО: Убедись что в bitcoin.conf указаны:
echo   server=1
echo   rpcuser=bitcoin
echo   rpcpassword=btc_hunter_2024
echo.

%PYTHON% btc_hunter_with_balance.py
pause
