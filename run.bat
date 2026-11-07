@echo off
REM BTC Key Hunter — запуск из исходников (требуется Python 3.9+)
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python не найден в PATH.
    echo Скачай Python с https://www.python.org/downloads/ и поставь галку "Add to PATH".
    pause
    exit /b 1
)

python -c "import rich" >nul 2>nul
if errorlevel 1 (
    echo Устанавливаю зависимости...
    python -m pip install -r requirements.txt
)

python btc_hunter_with_balance.py
pause
