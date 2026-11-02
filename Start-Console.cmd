@echo off
setlocal
rem Windows blocks scripts downloaded from the internet, and a script cannot unblock itself.
rem This unblocks the files in the tool's folder and opens the console. The execution policy stays as it is.
if not exist "%~dp0Agent365-Bulk-Actions.ps1" (
    echo Agent365-Bulk-Actions.ps1 is not next to this file. Extract the whole ZIP, then start this file from the extracted folder.
    pause
    exit /b 1
)
where pwsh >nul 2>nul
if errorlevel 1 (
    echo This tool needs PowerShell 7. To install it, run: winget install Microsoft.PowerShell
    echo Then start this file again.
    pause
    exit /b 1
)
set "A365_FOLDER=%~dp0"
pwsh -NoProfile -Command "Get-ChildItem -LiteralPath $env:A365_FOLDER -Recurse -File | Unblock-File"
pwsh -NoProfile -STA -File "%~dp0Agent365-Bulk-Actions.ps1" -Gui
if errorlevel 1 pause
