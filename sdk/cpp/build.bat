@echo off
REM Build the TrapKey SDK as a DLL plus the sample exe.
REM Requires "x64 Native Tools Command Prompt for VS 2022".

setlocal

if not exist build mkdir build

echo [1/2] TrapKey.dll
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /DTK_BUILD_DLL /LD ^
   trapkey.cpp ^
   /Fobuild\ ^
   /Fdbuild\trapkey.pdb ^
   /link /OUT:build\TrapKey.dll /IMPLIB:build\TrapKey.lib ^
   bcrypt.lib winhttp.lib advapi32.lib

if errorlevel 1 goto :fail

echo [2/2] sample.exe
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 ^
   sample\main.cpp ^
   /I. ^
   /Fobuild\ ^
   /link /OUT:build\sample.exe build\TrapKey.lib ^
   bcrypt.lib winhttp.lib advapi32.lib

if errorlevel 1 goto :fail

echo.
echo Build OK: build\TrapKey.dll, build\TrapKey.lib, build\sample.exe
echo Run:  build\sample.exe TK-XXXXX-XXXXX-XXXXX-XXXXX
exit /b 0

:fail
echo Build FAILED
exit /b 1
