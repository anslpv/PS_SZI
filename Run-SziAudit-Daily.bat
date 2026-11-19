@echo off
rem SZI-Audit: console mode for Windows Task Scheduler (run as administrator).
rem Edit PROFILE and the computer list file arm.txt (one name per line).
set PROFILE=ARM_OPK
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SziAudit.ps1" -NoGui -ProfileId %PROFILE% -ComputersFile "%~dp0arm.txt"
exit /b %ERRORLEVEL%
