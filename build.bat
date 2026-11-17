@echo off
REM ---------------------------------------------------------------------------
REM  FileLocker local build - run on a normal PC with Python 3.14 and internet.
REM  Same steps as the GitHub release workflow:
REM    hash-verified dependencies -> tests -> PyInstaller -> exe self-test -> zip
REM  Output: dist\FileLocker\  and  release\FileLocker-<version>-win64.zip
REM  Official releases are built by GitHub Actions; see VERIFYING.md.
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3.14"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python 3.14 was not found. Install it from https://www.python.org/ first.
    goto :fail
)
%PY% -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 14) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 3.14 is required - the dependency lock files are made for it.
    goto :fail
)

if not exist ".venv\Scripts\python.exe" (
    echo === Creating virtual environment .venv
    %PY% -m venv .venv || goto :fail
)
set "VPY=%~dp0.venv\Scripts\python.exe"

echo === Installing pinned, hash-verified dependencies
"%VPY%" -m pip install --require-hashes --no-deps -r requirements.txt -r requirements-build.txt -r requirements-test.txt || goto :fail

echo === Running tests
"%VPY%" tests\test_crypto.py || goto :testfail
"%VPY%" tests\test_no_network.py || goto :testfail

echo === Building
"%VPY%" scripts\build.py || goto :fail

echo.
echo === Build complete. Copy the whole "dist\FileLocker" folder, or send
echo     the zip in "release\", to the target computer.
endlocal
if not defined CI pause
exit /b 0

:testfail
echo [ERROR] Tests failed - not building.
:fail
echo.
echo Build FAILED.
endlocal
if not defined CI pause
exit /b 1
