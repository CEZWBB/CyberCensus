@echo off
rem NOTE: keep this file ASCII-only. Chinese comments in a UTF-8 bat get
rem truncated by cmd under GBK codepage and corrupt the commands below.
rem One-click GUI launcher (auto-installs customtkinter on first run).
cd /d "%~dp0"

rem check GUI dependency, install if missing
py -3.11 -c "import customtkinter" >nul 2>nul
if errorlevel 1 (
    echo First run: installing GUI dependency customtkinter ...
    py -3.11 -m ensurepip --upgrade >nul 2>nul
    py -3.11 -m pip install customtkinter
    echo.
)

rem prefer pyw launcher (no console window), fall back to pythonw
where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw -3.11 asm_gui.pyw
    exit /b 0
)

where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw asm_gui.pyw
    exit /b 0
)

rem last resort: console python
start "" py -3.11 asm_gui.pyw
