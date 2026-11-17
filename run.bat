@echo off
rem NOTE: keep this file ASCII-only. Non-ASCII bytes (e.g. Chinese) in a
rem UTF-8 bat get truncated by cmd under GBK codepage and break the script.
rem No args = open the GUI; with args = CLI mode, e.g.  run.bat -d xx.gov.cn
cd /d "%~dp0"

if "%~1"=="" (
    start "" pyw -3.11 asm_gui.pyw
    exit /b 0
)

chcp 65001 >nul
py -3.11 cybercensus.py %*
if errorlevel 9009 (
    python cybercensus.py %*
)

echo.
pause
