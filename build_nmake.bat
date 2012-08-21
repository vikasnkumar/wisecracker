@echo off
REM Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
REM All rights reserved.
REM 
REM Redistribution and use in source and binary forms, with or without
REM modification, are permitted provided that the following conditions are met:
REM 
REM     * Redistributions of source code must retain the above copyright
REM       notice, this list of conditions and the following disclaimer.
REM 
REM     * Redistributions in binary form must reproduce the above copyright
REM       notice, this list of conditions and the following disclaimer in the
REM       documentation and/or other materials provided with the distribution.
REM 
REM     * Neither the name of Selective Intellect LLC nor the
REM       names of its contributors may be used to endorse or promote products
REM       derived from this software without specific prior written permission.
REM 
REM THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
REM ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
REM WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
REM DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
REM DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
REM (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
REM LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
REM ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
REM (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
REM SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
REM 
REM ##############################################################
REM COPYRIGHT: 2011-2012 Selective Intellect LLC. All Rights Reserved
REM AUTHOR: Vikas Kumar
REM DATE: 21st Dec 2011
REM SOFTWARE: Wisecracker 
REM ##############################################################

if /i "%1" == "/?" goto :help
if /i "%1" == "/h" goto :help
if /i "%2" == "/?" goto :help
if /i "%2" == "/h" goto :help
if /i "%3" == "/?" goto :help
if /i "%3" == "/h" goto :help

REM get into the batch script directory first
pushd %~dp0

REM check build type
set BUILD_TYPE=MinSizeRel
if /i "%1" == "Debug" set BUILD_TYPE=Debug
if /i "%2" == "Debug" set BUILD_TYPE=Debug
if /i "%3" == "Debug" set BUILD_TYPE=Debug

set CURDIR=%~dp0\%BUILD_TYPE%_%PROCESSOR_ARCHITECTURE%
@echo "Using Build Directory %CURDIR%"
mkdir %CURDIR%
pushd %CURDIR%

REM force OPENCL_ROOT and OPENSSL_ROOT_DIR setup
if "%OPENCL_ROOT%" == "" goto :openclerr
if "%OPENSSL_ROOT_DIR%" == "" goto :opensslerr
if "%XXD%" == "" goto :xxderr

if not "%VS80COMNTOOLS%" == "" goto :vs80
if not "%VS90COMNTOOLS%" == "" goto :vs90
if not "%VS100COMNTOOLS%" == "" goto :vs100
if not "%VS110COMNTOOLS%" == "" goto :vs110

:unknownvs
@echo "Cannot find a supported Visual Studio install. Please install any of Visual Studio 2005, 2008, 2010 or 2012"
goto :error

:vs80
call "%VS80COMNTOOLS%\..\..\VC\vcvarsall.bat" %PROCESSOR_ARCHITECTURE% || goto :vserr
goto :cmake

:vs90
call "%VS90COMNTOOLS%\..\..\VC\vcvarsall.bat" %PROCESSOR_ARCHITECTURE% || goto :vserr
goto :cmake

:vs100
call "%VS100COMNTOOLS%\..\..\VC\vcvarsall.bat" %PROCESSOR_ARCHITECTURE% || goto :vserr
goto :cmake

:vs110
call "%VS110COMNTOOLS%\..\..\VC\vcvarsall.bat" %PROCESSOR_ARCHITECTURE% || goto :vserr
goto :cmake

:cmake
if /i "%1" == "Rebuild" del CMakeCache.txt
if /i "%2" == "Rebuild" del CMakeCache.txt
if /i "%3" == "Rebuild" del CMakeCache.txt
if /i "%1" == "All" del CMakeCache.txt
if /i "%2" == "All" del CMakeCache.txt
if /i "%3" == "All" del CMakeCache.txt
set NMFLAG=
if not exist CMakeCache.txt set NMFLAG=/A
@echo "NMake Flag is %NMFLAG%"

cmake -G"NMake Makefiles" -DCMAKE_INSTALL_PREFIX=wisecracker -DCMAKE_BUILD_TYPE="%BUILD_TYPE%" ..\ || goto :cmakeerr
nmake %NMFLAG% || goto :nmakeerr

REM check build target
if /i "%1" == "Test" ctest || goto :error
if /i "%2" == "Test" ctest || goto :error
if /i "%3" == "Test" ctest || goto :error
if /i "%1" == "All" ctest || goto :error
if /i "%2" == "All" ctest || goto :error
if /i "%3" == "All" ctest || goto :error
if /i "%1" == "Install" nmake install || goto :nmakeerr
if /i "%2" == "Install" nmake install || goto :nmakeerr
if /i "%3" == "Install" nmake install || goto :nmakeerr
if /i "%1" == "All" nmake install || goto :nmakeerr
if /i "%2" == "All" nmake install || goto :nmakeerr
if /i "%3" == "All" nmake install || goto :nmakeerr

REM done with processing
@echo "Success!"
goto :end

:openclerr
@echo "Please set the environment variable OPENCL_ROOT first"
goto :end

:opensslerr
@echo "Please set the environment variable OPENSSL_ROOT_DIR first"
goto :end

:xxderr
@echo "Please set the environment variable XXD to point to the full path of xxd.exe"
goto :end

:vserr
@echo "Unable to run the vcvarsall.bat script to load the Visual Studio environment"
goto :end

:cmakeerr
@echo "Unable to run the cmake successfully to generate NMake files"
goto :end

:nmakeerr
@echo "Unable to run NMake"
goto :end

:error
@echo "Error occurred."
goto :end

:help
@echo "Usage: %0 [/?|/h] [Debug|Release] [test|install|rebuild|all]"
goto :end

:end
REM pop out of the build directory
popd

REM pop out of the top level directory
popd
@echo:
pause
