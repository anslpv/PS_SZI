@echo off
rem SZI-Audit: console mode for Windows Task Scheduler (run as administrator).
rem Edit the computer list file arm.txt (one name per line, optionally "NAME;PROFILE_ID").
rem PROFILE is the default profile for computers listed without a profile id.
set PROFILE=ARM_OPK
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SziAudit.ps1" -NoGui -ProfileId %PROFILE% -ComputersFile "%~dp0arm.txt"
exit /b %ERRORLEVEL%
