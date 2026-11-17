@echo off
REM ---------------------------------------------------------------------------
REM  Fallback launcher: runs main.py with a portable (embeddable) Python that
REM  lives in the "python" subfolder next to this file. No installation needed.
REM  See README.md, section "Fallback: portable Python", for how to set it up.
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

if not exist "%~dp0python\python.exe" (
    echo [ERROR] Portable Python not found in "%~dp0python".
    echo         See README.md - "Fallback: portable Python".
    pause
    exit /b 1
)

"%~dp0python\python.exe" -c "import tkinter, msoffcrypto, pypdf, cryptography" 2>nul
if errorlevel 1 (
    echo [ERROR] The portable Python is missing tkinter or the required libraries.
    echo         Details:
    "%~dp0python\python.exe" -c "import tkinter, msoffcrypto, pypdf, cryptography"
    echo         See README.md - "Fallback: portable Python".
    pause
    exit /b 1
)

start "" "%~dp0python\pythonw.exe" "%~dp0main.py"
endlocal
