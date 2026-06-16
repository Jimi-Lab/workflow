@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "ENV_FILE=%SCRIPT_DIR%.env"
set "CONDA_ENV_NAME=%CONDA_ENV_NAME%"
if "%CONDA_ENV_NAME%"=="" set "CONDA_ENV_NAME=VulnVersion"

rem Always launch OpenCode from the project root so project-local .opencode\skills
rem are discovered regardless of the caller's current working directory.
cd /d "%SCRIPT_DIR%"

if exist "%ENV_FILE%" (
  echo Loading environment variables from "%ENV_FILE%"
  for /f "usebackq tokens=* delims=" %%L in ("%ENV_FILE%") do (
    set "LINE=%%L"
    if not "!LINE!"=="" (
      if not "!LINE:~0,1!"=="#" (
        for /f "tokens=1* delims==" %%A in ("!LINE!") do (
          set "NAME=%%A"
          set "VAL=%%B"
          if not "!NAME!"=="" (
            set "!NAME!=!VAL!"
          )
        )
      )
    )
  )
) else (
  echo .env file not found at "%ENV_FILE%". Starting OpenCode without loading .env.
)

if defined CONDA_EXE (
  set "CONDA_BIN=%CONDA_EXE%"
) else (
  where conda >nul 2>nul
  if errorlevel 1 (
    echo ERROR: conda executable not found in PATH.
    echo Install Conda/Miniforge first, then create the environment from environment.yml.
    echo You can also set CONDA_EXE explicitly.
    exit /b 1
  )
  set "CONDA_BIN=conda"
)

if defined OPENCODE_BIN (
  set "OPENCODE_CMD=%OPENCODE_BIN%"
) else (
  set "OPENCODE_CMD=opencode"
)

echo Starting OpenCode Server on http://127.0.0.1:4096 ...
echo Working directory: %CD%
echo Conda environment: %CONDA_ENV_NAME%
"%CONDA_BIN%" run --no-capture-output -n "%CONDA_ENV_NAME%" "%OPENCODE_CMD%" serve --hostname 127.0.0.1 --port 4096 --print-logs
