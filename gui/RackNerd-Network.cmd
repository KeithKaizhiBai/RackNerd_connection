@echo off
setlocal
set "RN_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 set "RN_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if "%~1"=="" goto panel
if /i "%~1"=="Panel" goto panel
if /i "%~1"=="Menu" goto panel
if /i "%~1"=="Status" goto status
if /i "%~1"=="Original" goto original
if /i "%~1"=="Test" goto trial
if /i "%~1"=="RackNerd" goto connect
echo Usage: RackNerd-Network.cmd [Menu ^| Panel ^| Status ^| Test ^| RackNerd ^| Original]
exit /b 2

:panel
if not exist "%~dp0Gateway-Panel.ps1" goto incomplete
start "" "%RN_PS%" -NoProfile -STA -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File "%~dp0Gateway-Panel.ps1"
exit /b %errorlevel%

:status
if not exist "%~dp0Gateway-Panel.ps1" goto incomplete
"%RN_PS%" -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0Gateway-Panel.ps1" -StatusOnly
exit /b %errorlevel%

:original
set "RN_ACTION=Original"
goto action
:trial
set "RN_ACTION=Test"
goto action
:connect
set "RN_ACTION=RackNerd"
:action
"%RN_PS%" -NoProfile -NonInteractive -Command "$f=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RackNerd-Connection\Gateway-Mode.ps1';if(-not (Test-Path -LiteralPath $f -PathType Leaf)){Write-Host 'First run windows\Install-Client.ps1.';exit 2};$a='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File '+[char]34+$f+[char]34+' -Action '+$env:RN_ACTION;try{$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Hidden -ArgumentList $a -Wait -PassThru -ErrorAction Stop;exit $p.ExitCode}catch{Write-Host 'The administrator operation did not start.';exit 1}"
exit /b %errorlevel%

:incomplete
echo Gateway-Panel.ps1 is missing. Keep the files in the gui folder together.
exit /b 2
