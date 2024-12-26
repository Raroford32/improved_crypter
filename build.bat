@echo off
echo Initializing Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

echo Configuring CMake...
cmake -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release

echo Building project...
cmake --build build --config Release --verbose

if %ERRORLEVEL% NEQ 0 (
    echo Failed to build project
    exit /b %ERRORLEVEL%
)

echo Copying resources...
xcopy /y resources\* build\

echo Build completed successfully
