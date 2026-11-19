@echo off
rem SZI-Audit launcher: starts the GUI with PowerShell 5.1 (STA mode required by WPF)
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0SziAudit.ps1"
