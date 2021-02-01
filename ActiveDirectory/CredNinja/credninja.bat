@echo off
setlocal
cd /d %~dp0
C:\Windows\System32\cmd.exe /K powershell.exe -NoExit -Command " .\Invoke-CredNinja.ps1 