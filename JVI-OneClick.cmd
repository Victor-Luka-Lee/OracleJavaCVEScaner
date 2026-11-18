@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

if exist "%~dp0JVI.exe" (
  "%~dp0JVI.exe"
  set "JVI_EXIT=%ERRORLEVEL%"
) else (
  where python >nul 2>nul
  if not errorlevel 1 (
    python -m jvi
    set "JVI_EXIT=%ERRORLEVEL%"
  ) else (
    where py >nul 2>nul
    if not errorlevel 1 (
      py -m jvi
      set "JVI_EXIT=%ERRORLEVEL%"
    ) else (
      echo Python or JVI.exe was not found.
      set "JVI_EXIT=2"
    )
  )
)

echo.
echo Press Enter to close this window.
pause >nul
exit /b %JVI_EXIT%
