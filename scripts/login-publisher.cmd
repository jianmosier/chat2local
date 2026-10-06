@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0.."
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found. No configuration changed.
  exit /b 1
)
if not exist "node_modules\wrangler\bin\wrangler.js" (
  echo Project Wrangler is missing. No packages were installed.
  exit /b 1
)
if /I "%~1"=="--check" (
  echo Publisher login launcher ready. No login or deployment performed.
  exit /b 0
)
if not "%~1"=="" (
  echo Unknown argument.
  exit /b 1
)
echo Chat2Local - authorize the existing Cloudflare publisher.
echo Use the account that owns the existing Worker. Do not create another account.
echo This only starts normal OAuth login. It does not deploy or accept permissions for you.
echo No API token needs to be copied into ChatGPT.
if defined HTTP_PROXY goto proxy
if defined HTTPS_PROXY goto proxy
node node_modules\wrangler\bin\wrangler.js login --scopes account:read user:read workers_scripts:write workers_kv:write workers_routes:write
goto done
:proxy
node --use-env-proxy --import ./scripts/maintainer-tls-compat.mjs node_modules\wrangler\bin\wrangler.js login --scopes account:read user:read workers_scripts:write workers_kv:write workers_routes:write
:done
set "LOGIN_EXIT=%ERRORLEVEL%"
echo.
if "%LOGIN_EXIT%"=="0" (echo Login completed. Return to the existing ChatGPT conversation.) else (echo Login did not complete. Keep this window and report the non-secret error.)
pause
exit /b %LOGIN_EXIT%
