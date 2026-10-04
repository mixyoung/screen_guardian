@echo off
setlocal
pushd "%~dp0.." || exit /b 1
"bin\screen-guardian-cli.exe" %*
set "SG_EC=%ERRORLEVEL%"
popd
exit /b %SG_EC%
