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
### COPYRIGHT: Selective Intellect LLC
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
#########################################################################

if (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -pedantic -std=c99 -Wno-comment")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pedantic -Wno-comment")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		message(STATUS "Performing Debug build using GCC suite")
		set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -fno-inline")
	endif (CMAKE_BUILD_TYPE STREQUAL "Debug")
	if (ARCH STREQUAL "x86_64")
		message(STATUS "Compiling for ${ARCH}")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
	else (ARCH STREQUAL "x86_64")
		message(STATUS "Compiling for ${ARCH}")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
	endif (ARCH STREQUAL "x86_64")
endif (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUC)

if (WIN32 AND MSVC)
    foreach(flag_var
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif(${flag_var} MATCHES "/MD")
        set(${flag_var} "${${flag_var}} /EHsc")
    endforeach(flag_var)
	if (CMAKE_CL_64)
		set(ARCH "x86_64")
		set(WINARCH "Win64")
		set(WINARCH2 "x64")
	else (CMAKE_CL_64)
		set(ARCH "x86")
		set(WINARCH "Win32")
		set(WINARCH2 "x86")
	endif (CMAKE_CL_64)
	message(STATUS "Architecture is ${WINARCH}")
endif (WIN32 AND MSVC)

check_include_file("windows.h" WC_WINDOWS_H)
check_include_file("errno.h" WC_ERRNO_H)
check_include_file("unistd.h" WC_UNISTD_H)
check_include_file("stdio.h" WC_STDIO_H)
check_include_file("stdlib.h" WC_STDLIB_H)
check_include_file("string.h" WC_STRING_H)
check_include_file("malloc.h" WC_MALLOC_H)
check_include_file("stdint.h" WC_STDINT_H)
check_include_file("assert.h" WC_ASSERT_H)
check_include_file("ctype.h" WC_CTYPE_H)
check_include_file("time.h" WC_TIME_H)
check_include_file("sys/types.h" WC_SYSTYPES_H)
check_include_file("sys/time.h" WC_SYSTIME_H)
check_include_file("sys/timeb.h" WC_SYSTIMEB_H)
check_include_file("stdarg.h" WC_STDARG_H)
check_include_file("sys/stat.h" WC_SYSSTAT_H)
check_include_file("getopt.h" WC_GETOPT_H)
check_include_file("inttypes.h" WC_INTTYPES_H)
check_include_files("windows.h;shlwapi.h" WC_SHLWAPI_H)
check_include_file("pthread.h" WC_PTHREAD_H)
if (APPLE)
	check_include_file("libgen.h" WC_LIBGEN_H)
endif (APPLE)
# this is temporary for just verification
if (USE_OPENSSL)
	include(FindOpenSSL)
	if (OPENSSL_FOUND)
		include_directories(${OPENSSL_INCLUDE_DIR})
		set(CMAKE_REQUIRED_INCLUDES_SAVE ${CMAKE_REQUIRED_INCLUDES})
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES}
			${OPENSSL_INCLUDE_DIR})
		check_include_file("openssl/md5.h" WC_OPENSSL_MD5_H)
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_SAVE})
		if (APPLE)
			if (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUC)
				set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
				set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
			endif (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUC)
		endif (APPLE)
		if (WIN32)
			set(OPENSSL_LIBNAME
				"${CMAKE_SHARED_LIBRARY_PREFIX}libeay32${CMAKE_SHARED_LIBRARY_SUFFIX}")
			if (OPENSSL_ROOT_DIR)
				set(OPENSSL_ROOT ${OPENSSL_ROOT_DIR})
			else (OPENSSL_ROOT_DIR)
				if (EXISTS "C:/OpenSSL-${WINARCH}")
					set(OPENSSL_ROOT "C:/OpenSSL-${WINARCH}")
				else (EXISTS "C:/OpenSSL-${WINARCH}")
					set(OPENSSL_ROOT $ENV{OPENSSL_ROOT})
				endif (EXISTS "C:/OpenSSL-${WINARCH}")
			endif (OPENSSL_ROOT_DIR)
			if (OPENSSL_ROOT)
				message(STATUS "OpenSSL from: ${OPENSSL_ROOT}")
				set(OPENSSL_SHARED ${OPENSSL_ROOT}/bin/${OPENSSL_LIBNAME})
				message(STATUS "Using ${OPENSSL_SHARED}")
				file(COPY ${OPENSSL_SHARED} DESTINATION ${WC_SRCBIN_DIR})
				file(COPY ${OPENSSL_SHARED} DESTINATION ${WC_APPSBIN_DIR})
				install(PROGRAMS ${OPENSSL_SHARED} DESTINATION bin)
			else (OPENSSL_ROOT)
				message(WARNING "Cannot find  ${OPENSSL_LIBNAME}. Please place it "
					" in %PATH% before using the software or set the OPENSSL_ROOT"
					" environment variable and rerun this script.")
			endif (OPENSSL_ROOT)
		endif (WIN32)
	endif (OPENSSL_FOUND)
endif (USE_OPENSSL)

if (NOT CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/wisecracker)
else (NOT CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_PREFIX_SAVE ${CMAKE_INSTALL_PREFIX})
	file(TO_CMAKE_PATH ${CMAKE_INSTALL_PREFIX_SAVE} CMAKE_INSTALL_PREFIX)
endif (NOT CMAKE_INSTALL_PREFIX)
include(InstallRequiredSystemLibraries)

if (WIN32)
	# for WIN32 this is needed
	set(XXD_ENV $ENV{XXD})
	if (NOT XXD_ENV)
		message(FATAL_ERROR "Please set the environment variable XXD to point "
				"to xxd.exe")
	endif (NOT XXD_ENV)
	file (TO_CMAKE_PATH ${XXD_ENV} XXD)
	if (WC_SHLWAPI_H)
		set(OS_LIBS ${OS_LIBS} shlwapi)
	endif (WC_SHLWAPI_H)
else (WIN32)
	# for UNIX this is already available
	find_program(XXD xxd)
	set(OS_LIBS ${OS_LIBS} pthread)
endif (WIN32)
if (XXD STREQUAL "XXD-NOTFOUND")
	message(FATAL_ERROR "Please install the commandline tool xxd.")
else (XXD STREQUAL "XXD-NOTFOUND")
	message(STATUS "Found xxd at ${XXD}")
endif (XXD STREQUAL "XXD-NOTFOUND")
