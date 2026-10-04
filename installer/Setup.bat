@echo off
setlocal
set "INSTALL_DIR=%LOCALAPPDATA%\Programs\Netra AI"

if not defined LOCALAPPDATA (
  echo Could not find the current user's Local AppData folder.
  goto :failed
)

pushd "%~dp0"
if errorlevel 1 (
  echo Could not open the extracted Netra AI folder.
  goto :failed
)
set "SOURCE_DIR=%CD%"

if not exist "%SOURCE_DIR%\NetraAI.exe" (
  echo NetraAI.exe was not found. Extract the complete download before running Setup.bat.
  goto :failed_pushed
)

if not exist "%SOURCE_DIR%\_internal" (
  echo The application files are incomplete. Extract the complete download before running Setup.bat.
  goto :failed_pushed
)

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if errorlevel 1 (
  echo Could not create the installation folder: "%INSTALL_DIR%"
  goto :failed_pushed
)

robocopy "%SOURCE_DIR%" "%INSTALL_DIR%" /E /R:2 /W:1 /XF Setup.bat
if errorlevel 8 (
  echo.
  echo Could not copy Netra AI into "%INSTALL_DIR%".
  echo Check the copy error above, close any running Netra AI windows, and try again.
  goto :failed_pushed
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $shell=New-Object -ComObject WScript.Shell; $shortcut=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'NetraAI.lnk')); $shortcut.TargetPath=(Join-Path $env:LOCALAPPDATA 'Programs\Netra AI\NetraAI.exe'); $shortcut.WorkingDirectory=(Join-Path $env:LOCALAPPDATA 'Programs\Netra AI'); $shortcut.Description='Start Netra AI local network dashboard'; $shortcut.Save()"
if errorlevel 1 (
  echo Netra AI was installed, but Windows could not create the desktop shortcut.
  echo You can still start it from "%INSTALL_DIR%\NetraAI.exe".
  goto :failed_pushed
)

popd
echo Netra AI is installed. Starting the app now...
start "" "%INSTALL_DIR%\NetraAI.exe"
exit /b 0

:failed_pushed
popd
:failed
pause
exit /b 1
