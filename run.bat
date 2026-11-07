@echo off
REM BTC Key Hunter v2.0 — Python 3.12.10 (самый стабильный)
setlocal
cd /d "%~dp0"

set PYTHON="C:\Users\User3\AppData\Local\Programs\Python\Python312\python.exe"

if not exist %PYTHON% (
    echo ERROR: Python 3.12.10 не найден!
    pause
    exit /b 1
)

%PYTHON% launcher.py
if errorlevel 1 %PYTHON% btc_hunter_cli.py
pause
