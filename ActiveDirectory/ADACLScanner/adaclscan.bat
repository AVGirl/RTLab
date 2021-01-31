@echo off
setlocal
cd /d %~dp0
powershell.exe -ExecutionPolicy Bypass -NoExit -Command " .\ADACLScan.ps1