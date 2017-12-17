@rem Copyright 2017 Neo Natura
@echo off

set PKG=ShareCoin
set VER=2.29

set WIX="C:\program files (x86)\wix toolset v3.11\bin"
set BUILD=C:\msys64\home\root\src\share-coin\build
set RELEASE=C:\release\share-coin\bin

copy /y %BUILD%\src\share-coin\.libs\shcoind.exe > nul
copy /y %BUILD%\src\coin-console\.libs\shcointool.exe > nul
move /y shcointool.exe shc.exe > nul
move /y shcoind.exe %RELEASE% > nul
move /y shc.exe %RELEASE% > nul

%WIX%\candle -nologo share-coin.xml
%WIX%\light -nologo share-coin.wixobj
move /y share-coin.msi %PKG%-%VER%.msi
move /y %PKG%-%VER%.msi %RELEASE%
