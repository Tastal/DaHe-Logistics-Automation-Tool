@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 exit /b %errorlevel%
)

".venv\Scripts\python.exe" -m pip install --no-cache-dir --retries 2 --timeout 30 pip==26.1.2
if errorlevel 1 exit /b %errorlevel%

".venv\Scripts\python.exe" -m pip install --no-cache-dir --retries 2 --timeout 30 -r requirements.lock
if errorlevel 1 exit /b %errorlevel%

".venv\Scripts\python.exe" -m pip install --no-cache-dir --no-build-isolation --no-deps -e .
if errorlevel 1 exit /b %errorlevel%

call npm.cmd --prefix frontend ci --ignore-scripts --cache frontend\.npm-cache
if errorlevel 1 exit /b %errorlevel%

".venv\Scripts\python.exe" tools\check.py
