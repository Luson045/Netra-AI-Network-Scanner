@echo off
setlocal
set "ROOT=%~dp0"
set "BACKEND=%ROOT%backend"
set "PYTHON=%BACKEND%\.venv\Scripts\python.exe"
set "STAGING=%TEMP%\NetraAI-release-%RANDOM%-%RANDOM%"

if not exist "%PYTHON%" (
  echo Creating the build environment...
  py -3 -m venv "%BACKEND%\.venv"
  if errorlevel 1 (
    echo Python 3 is required. Install Python 3.10 or newer and enable the py launcher.
    exit /b 1
  )
)

mkdir "%STAGING%"
if errorlevel 1 exit /b 1

echo Installing build dependencies...
"%PYTHON%" -m pip install -r "%BACKEND%\requirements-build.txt"
if errorlevel 1 (
  rmdir /s /q "%STAGING%"
  exit /b 1
)

echo Building NetraAI.exe...
pushd "%BACKEND%"
"%PYTHON%" -m PyInstaller --noconfirm --clean --onedir --name NetraAI --workpath "%STAGING%\build" --distpath "%STAGING%\dist" --specpath "%STAGING%" --collect-submodules app --collect-submodules uvicorn --collect-submodules sqlalchemy --collect-submodules pydantic_settings --collect-all aiosqlite --add-data "%BACKEND%\app\static;app\static" run_local.py
set "BUILD_RESULT=%ERRORLEVEL%"
popd
if not "%BUILD_RESULT%"=="0" (
  rmdir /s /q "%STAGING%"
  exit /b %BUILD_RESULT%
)

robocopy "%STAGING%\dist\NetraAI" "%STAGING%\package" /E /R:2 /W:1 >nul
if errorlevel 8 (
  rmdir /s /q "%STAGING%"
  exit /b 1
)
copy "%ROOT%installer\Setup.bat" "%STAGING%\package\Setup.bat" >nul
if errorlevel 1 (
  rmdir /s /q "%STAGING%"
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%STAGING%\package\*' -DestinationPath '%ROOT%NetraAI-Windows.zip' -CompressionLevel Optimal -Force"
set "PACKAGE_RESULT=%ERRORLEVEL%"
rmdir /s /q "%STAGING%"
if not "%PACKAGE_RESULT%"=="0" exit /b %PACKAGE_RESULT%

echo.
echo Release package created: "%ROOT%NetraAI-Windows.zip"
exit /b 0
