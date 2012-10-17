### Wisecracker: A cryptanalysis framework
### Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
###    
###	This program is free software: you can redistribute it and/or modify
### it under the terms of the GNU General Public License as published by
### the Free Software Foundation, either version 3 of the License, or
### any later version.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.
###
### You should have received a copy of the GNU General Public License
### along with this program.  If not, see <http://www.gnu.org/licenses/>.
#########################################################################
### COPYRIGHT: 2011-2012 Selective Intellect LLC. All Rights Reserved
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
### SOFTWARE: Wisecracker 
#########################################################################
cmake_minimum_required(VERSION 2.6)

#CMake default includes
include(CTest)
enable_testing()
if (CMAKE_MINOR_VERSION GREATER 6)
	cmake_policy(SET CMP0008 OLD)
endif (CMAKE_MINOR_VERSION GREATER 6)

include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckFunctionExists)
option(USE_OPENSSL "Use OpenSSL" ON)
if (APPLE OR WIN32)
	option(USE_MPI "Use MPI" OFF)
else (APPLE OR WIN32)
	option(USE_MPI "Use MPI" ON)
endif (APPLE OR WIN32)

# Custom includes
set(WC_SRCBIN_DIR ${CMAKE_CURRENT_BINARY_DIR}/src)
set(WC_APPSBIN_DIR ${CMAKE_CURRENT_BINARY_DIR}/apps)
include(deps/osdefaults.cmake)
if (WIN32)
	include(deps/openclwin.cmake)
else (WIN32)
	include(deps/opencl.cmake)
endif (WIN32)
include(deps/mpi.cmake)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(apps)
