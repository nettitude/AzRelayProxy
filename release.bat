@echo off
echo Building Windows x64...
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish\win-x64

echo Building Linux x64...
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish\linux-x64

echo.
echo Output:
echo   publish\win-x64\RelayProxy.exe
echo   publish\linux-x64\RelayProxy
