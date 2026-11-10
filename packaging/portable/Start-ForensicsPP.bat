@echo off
rem Copyright (c) 2026 DyNooob. MIT License.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 start_server.py %*
) else (
  python start_server.py %*
)
if errorlevel 1 pause
