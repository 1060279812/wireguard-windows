@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.

setlocal enabledelayedexpansion
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%.deps\llvm-mingw\bin;%BUILDDIR%.deps\go\bin;%BUILDDIR%.deps;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

if exist .deps\prepared goto :render
:installdeps
    rmdir /s /q .deps 2> NUL
    mkdir .deps || goto :error
    cd .deps || goto :error
    call :copy_local go.zip D:\wireguard\wireguard-windows-depend\go1.23.4.windows-amd64.zip 16c59ac9196b63afb872ce9b47f945b9821a3e1542ec125f16f6085a1c0f3c39 || goto :error
    call :copy_local llvm-mingw-msvcrt.zip D:\wireguard\wireguard-windows-depend\llvm-mingw-20201020-msvcrt-x86_64.zip 2e46593245090df96d15e360e092f0b62b97e93866e0162dca7f93b16722b844 || goto :error
    call :copy_local imagemagick.zip D:\wireguard\wireguard-windows-depend\ImageMagick-7.0.8-42-portable-Q16-x64.zip 584e069f56456ce7dde40220948ff9568ac810688c892c5dfb7f6db902aa05aa "convert.exe colors.xml delegates.xml" || goto :error
    call :copy_local make.zip D:\wireguard\wireguard-windows-depend\make-4.2.1-without-guile-w32-bin.zip 30641be9602712be76212b99df7209f4f8f518ba764cf564262bc9d6e4047cc7 "--strip-components 1 bin" || goto :error
    call :copy_local wireguard-tools.zip D:\wireguard\wireguard-windows-depend\wireguard-tools.zip ed0739bc3e5a7021a59d4cc4fc63e5fb60a0cb8628d30515a747bfbdcf1fdb0a "--exclude wg-quick --strip-components 1" || goto :error
    call :copy_local wireguard-nt.zip D:\wireguard\wireguard-windows-depend\wireguard-nt.zip a33e10f24360bc48f13098285c47443b5c6e5068423322f2f51c25e20dd8aca8 || goto :error
    copy /y NUL prepared > NUL || goto :error
    cd .. || goto :error

@REM Get-FileHash "D:\wireguard\wireguard-windows-depend\wireguard-nt" -Algorithm SHA256   需要大小写转换

:render
    echo [+] Rendering icons
    for %%a in ("ui\icon\*.svg") do convert -background none "%%~fa" -define icon:auto-resize="256,192,128,96,64,48,40,32,24,20,16" -compress zip "%%~dpna.ico" || goto :error

:build
    for /f "tokens=3" %%a in ('findstr /r "Number.*=.*[0-9.]*" .\version\version.go') do set WIREGUARD_VERSION=%%a
    set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%
    for /f "tokens=1-4" %%a in ("%WIREGUARD_VERSION:.= % 0 0 0") do set WIREGUARD_VERSION_ARRAY=%%a,%%b,%%c,%%d
    set GOOS=windows
    set GOARM=7
    set GOPATH=%BUILDDIR%.deps\gopath
    set GOROOT=%BUILDDIR%.deps\go
    if "%GoGenerate%"=="yes" (
        echo [+] Regenerating files
        go generate ./... || exit /b 1
    )
    call :build_plat x86 i686 386 || goto :error
    call :build_plat amd64 x86_64 amd64 || goto :error
    call :build_plat arm64 aarch64 arm64 || goto :error

:sign
    if exist .\sign.bat call .\sign.bat
    if "%SigningProvider%"=="" goto :success
    if "%TimestampServer%"=="" goto :success
    echo [+] Signing
    signtool sign %SigningProvider% /fd sha256 /tr "%TimestampServer%" /td sha256 /d WireGuard x86\wireguard.exe x86\wg.exe amd64\wireguard.exe amd64\wg.exe arm64\wireguard.exe arm64\wg.exe || goto :error

:success
    echo [+] Success. Launch wireguard.exe.
    exit /b 0

:copy_local
    echo [+] Copying %1 from local repository
    copy %2 %1 || exit /b 1
    echo [+] Verifying %1
    for /f %%a in ('CertUtil -hashfile %1 SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="%~3" exit /b 1
    echo [+] Extracting %1
    tar -xf %1 %~4 || exit /b 1
    echo [+] Cleaning up %1
    del %1 || exit /b 1
    goto :eof

:build_plat
    set GOARCH=%~3
    mkdir %1 >NUL 2>&1
    echo [+] Assembling resources %1
    %~2-w64-mingw32-windres -I ".deps\wireguard-nt\bin\%~1" -DWIREGUARD_VERSION_ARRAY=%WIREGUARD_VERSION_ARRAY% -DWIREGUARD_VERSION_STR=%WIREGUARD_VERSION% -i resources.rc -o "resources_%~3.syso" -O coff || exit /b 1
    echo [+] Building program %1
    go build -tags load_wgnt_from_rsrc -ldflags="-H windowsgui -s -w" -trimpath -buildvcs=false -v -o "%~1\wireguard.exe" || exit /b 1
    if not exist "%~1\wg.exe" (
        echo [+] Building command line tools %1
        del .deps\src\*.exe .deps\src\*.o .deps\src\wincompat\*.o .deps\src\wincompat\*.lib 2> NUL
        set LDFLAGS=-s
        make --no-print-directory -C .deps\src PLATFORM=windows CC=%~2-w64-mingw32-gcc WINDRES=%~2-w64-mingw32-windres V=1 RUNSTATEDIR= SYSTEMDUNITDIR= -j%NUMBER_OF_PROCESSORS% || exit /b 1
        move /Y .deps\src\wg.exe "%~1\wg.exe" > NUL || exit /b 1
    )
    goto :eof

:error
    echo [-] Failed with error #%errorlevel%.
    cmd /c exit %errorlevel%