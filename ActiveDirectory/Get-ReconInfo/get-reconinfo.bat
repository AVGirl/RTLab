@echo off
cd /d %~dp0
C:\Windows\System32\cmd.exe /K powershell.exe -NoExit -Command "Import-Module .\Get-ReconInfo.ps1; Get-ReconInfo"