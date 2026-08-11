@echo off
setlocal
set "PROJECT_ROOT=%~dp0.."
set "PROJECT_PYTHON=%PROJECT_ROOT%\.venv\Scripts\python.exe"

if not exist "%PROJECT_PYTHON%" (
  echo Project virtual environment is missing. Run tools\bootstrap.cmd first. 1>&2
  exit /b 2
)

"%PROJECT_PYTHON%" "%~dp0bootstrap_ocr.py" %*
exit /b %ERRORLEVEL%
