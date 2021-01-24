@rem Copyright 2017 Neo Natura
@echo off

set PKG=shioncoin
set VER=4.2

set SDK="C:\Program Files (x86)\Windows Kits\10\App Certification Kit\"
set WIX="C:\program files (x86)\wix toolset v3.11\bin"
set BUILD=C:\msys64\home\root\src\shioncoin\build
set RELEASE=C:\release\shioncoin\bin

copy /y %BUILD%\src\shioncoin\shcoind.exe > nul
copy /y %BUILD%\src\shioncoin\.libs\shcoind.exe > nul
copy /y %BUILD%\src\coin-console\shc.exe > nul
copy /y %BUILD%\src\coin-console\.libs\shc.exe > nul
move /y shcoind.exe %RELEASE% > nul
move /y shc.exe %RELEASE% > nul

%WIX%\candle -nologo -ext "c:\Program Files (x86)\WiX Toolset v3.11\bin\WixUtilExtension.dll" shioncoin.xml
%WIX%\light -nologo -ext "c:\Program Files (x86)\WiX Toolset v3.11\bin\WixUtilExtension.dll" shioncoin.wixobj
move /y shioncoin.msi %PKG%-%VER%.msi
move /y %PKG%-%VER%.msi %RELEASE%

rem %SDK%\signtool.exe sign /f "c:\certificates\neonatura.pfx" /p %1 /d "Neo Natura" /t http://timestamp.verisign.com/scripts/timstamp.dll /v %PKG%-%VER%.msi
