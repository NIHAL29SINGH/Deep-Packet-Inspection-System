@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "wantMetrics=0"
set "cleanArgs="
for %%A in (%*) do (
  set "tok=%%~A"
  if /I "!tok!"=="metrics" (
    set "wantMetrics=1"
  ) else if /I "!tok!"=="metrices" (
    set "wantMetrics=1"
  ) else if /I "!tok!"=="-metrics" (
    set "wantMetrics=1"
  ) else if /I "!tok!"=="-metrices" (
    set "wantMetrics=1"
  ) else (
    set "cleanArgs=!cleanArgs! %%~A"
  )
)
if "!wantMetrics!"=="1" (
  "%~dp0metrics.cmd" start
  start "" http://localhost:3001
  powershell -ExecutionPolicy Bypass -File "%~dp0report.ps1" !cleanArgs! -Monitor -NoBench
  exit /b %errorlevel%
)
powershell -ExecutionPolicy Bypass -File "%~dp0report.ps1" %*
