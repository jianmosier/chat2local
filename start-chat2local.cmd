@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
if exist "%~dp0runtime\node.exe" (
  "%~dp0runtime\node.exe" "%~dp0scripts\launch.mjs"
) else (
  where node.exe >nul 2>nul
  if errorlevel 1 (
    echo Chat2Local: this is the source package, not the Windows portable package.
    echo Please use Chat2Local-Windows-x64.zip, extract ALL files, then double-click this file.
    echo No settings were changed.
    pause
    exit /b 1
  )
  node.exe "%~dp0scripts\launch.mjs"
)
if errorlevel 1 (
  echo.
  echo Chat2Local did not confirm startup. The error above explains what happened.
  pause
  exit /b 1
)
exit /b 0
