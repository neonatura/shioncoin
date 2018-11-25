@rem Copyright 2017 Neo Natura
@echo off

set PKG=ShareCoin
set VER=3.02

set WIX="C:\program files (x86)\wix toolset v3.11\bin"
set BUILD=C:\msys64\home\root\src\share-coin\build
set RELEASE=C:\release\share-coin\bin

copy /y %BUILD%\src\share-coin\.libs\shcoind.exe > nul
copy /y %BUILD%\src\coin-console\.libs\shc.exe > nul
move /y shcoind.exe %RELEASE% > nul
move /y shc.exe %RELEASE% > nul

%WIX%\candle -nologo -ext "c:\Program Files (x86)\WiX Toolset v3.11\bin\WixUtilExtension.dll" share-coin.xml
%WIX%\light -nologo -ext "c:\Program Files (x86)\WiX Toolset v3.11\bin\WixUtilExtension.dll" share-coin.wixobj
move /y share-coin.msi %PKG%-%VER%.msi
move /y %PKG%-%VER%.msi %RELEASE%
