@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.

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
	call :download go.zip https://golang.org/dl/go1.17.windows-amd64.zip 2a18bd65583e221be8b9b7c2fbe3696c40f6e27c2df689bbdcc939d49651d151 || goto :error
	rem Mirror of https://github.com/mstorsjo/llvm-mingw/releases/download/20201020/llvm-mingw-20201020-msvcrt-x86_64.zip
	call :download llvm-mingw-msvcrt.zip https://download.wireguard.com/windows-toolchain/distfiles/llvm-mingw-20201020-msvcrt-x86_64.zip 2e46593245090df96d15e360e092f0b62b97e93866e0162dca7f93b16722b844 || goto :error
	rem Mirror of https://imagemagick.org/download/binaries/ImageMagick-7.0.8-42-portable-Q16-x64.zip
	call :download imagemagick.zip https://download.wireguard.com/windows-toolchain/distfiles/ImageMagick-7.0.8-42-portable-Q16-x64.zip 584e069f56456ce7dde40220948ff9568ac810688c892c5dfb7f6db902aa05aa "convert.exe colors.xml delegates.xml" || goto :error
	rem Mirror of https://sourceforge.net/projects/ezwinports/files/make-4.2.1-without-guile-w32-bin.zip
	call :download make.zip https://download.wireguard.com/windows-toolchain/distfiles/make-4.2.1-without-guile-w32-bin.zip 30641be9602712be76212b99df7209f4f8f518ba764cf564262bc9d6e4047cc7 "--strip-components 1 bin" || goto :error
	call :download wireguard-tools.zip https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-52597c351554ec7f39c0817d45771d1f30572f4b.zip c869f539dee0f5d4028d2d33f931c548c3aa5a22fe01ee4b28ffa01ffb33b8c9 "--exclude wg-quick --strip-components 1" || goto :error
	rem Mirror of https://sourceforge.net/projects/gnuwin32/files/patch/2.5.9-7/patch-2.5.9-7-bin.zip with fixed manifest
	call :download patch.zip https://download.wireguard.com/windows-toolchain/distfiles/patch-2.5.9-7-bin-fixed-manifest.zip 25977006ca9713f2662a5d0a2ed3a5a138225b8be3757035bd7da9dcf985d0a1 "--strip-components 1 bin" || goto :error
	call :download wintun.zip https://www.wintun.net/builds/wintun-0.13.zip 34afe7d0de1fdb781af3defc0a75fd8c97daa756279b42dd6be6a1bd8ccdc7f0 || goto :error
	call :download wireguard-nt.zip https://download.wireguard.com/wireguard-nt/wireguard-nt-0.5.zip bf29e3f97a23db84379f6c2e7057cd1cc32c40a8b2d89a90c8a4463ce5dd3e83 || goto :error
	echo [+] Patching go
	for %%a in ("..\go-patches\*.patch") do .\patch.exe -f -N -r- -d go -p1 --binary < "%%a" || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

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
	call :build_plat arm armv7 arm || goto :error
	call :build_plat arm64 aarch64 arm64 || goto :error

:sign
	if exist .\sign.bat call .\sign.bat
	if "%SigningCertificate%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing
	signtool sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d WireGuard x86\wireguard.exe x86\wg.exe amd64\wireguard.exe amd64\wg.exe arm\wireguard.exe arm\wg.exe arm64\wireguard.exe arm64\wg.exe || goto :error

:success
	echo [+] Success. Launch wireguard.exe.
	exit /b 0

:download
	echo [+] Downloading %1
	curl -#fLo %1 %2 || exit /b 1
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
	%~2-w64-mingw32-windres -I ".deps\wintun\bin\%~1" -I ".deps\wireguard-nt\bin\%~1" -DWIREGUARD_VERSION_ARRAY=%WIREGUARD_VERSION_ARRAY% -DWIREGUARD_VERSION_STR=%WIREGUARD_VERSION% -i resources.rc -o "resources_%~3.syso" -O coff -c 65001 || exit /b %errorlevel%
	echo [+] Building program %1
	go build -tags load_wintun_from_rsrc,load_wgnt_from_rsrc -ldflags="-H windowsgui -s -w" -trimpath -v -o "%~1\wireguard.exe" || exit /b 1
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
