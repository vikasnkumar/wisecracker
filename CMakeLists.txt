########################################
### COPYRIGHT: 2011-2012 Selective Intellect LLC. All Rights Reserved
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
### SOFTWARE: Wisecracker 
########################################
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

# Custom includes
include(deps/osdefaults.cmake)
include(deps/opencl.cmake)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)

add_subdirectory(include)
add_subdirectory(src)
