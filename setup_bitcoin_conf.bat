@echo off
REM Создаёт bitcoin.conf с RPC-доступом для BTC Key Hunter.
REM Ничего не трогает, если файл уже существует — просто покажет, что туда добавить.
setlocal

set "BTC_DIR=%APPDATA%\Bitcoin"
set "BTC_CONF=%BTC_DIR%\bitcoin.conf"

if exist "%BTC_CONF%" (
    echo Файл уже существует: %BTC_CONF%
    echo.
    echo Убедись, что в нём есть эти строки ^(добавь вручную, если нет^):
    echo.
    echo   server=1
    echo   rpcuser=bitcoin
    echo   rpcpassword=btc_hunter_2024
    echo   rpcallowip=127.0.0.1
    echo   rpcport=8332
    echo.
    pause
    exit /b 0
)

if not exist "%BTC_DIR%" mkdir "%BTC_DIR%"

(
    echo server=1
    echo rpcuser=bitcoin
    echo rpcpassword=btc_hunter_2024
    echo rpcallowip=127.0.0.1
    echo rpcport=8332
) > "%BTC_CONF%"

echo Создан: %BTC_CONF%
echo Перезапусти Bitcoin Core, чтобы настройки применились.
pause
