########################################
### COPYRIGHT: Selective Intellect LLC
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
########################################

if (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -pedantic -std=c99 -Wno-comment")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pedantic -Wno-comment")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		message(STATUS "Performing Debug build using GCC suite")
		set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -fno-inline")
	endif (CMAKE_BUILD_TYPE STREQUAL "Debug")
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
check_include_file("stdarg.h" WC_STDARG_H)
check_include_file("sys/stat.h" WC_SYSSTAT_H)
check_include_file("getopt.h" WC_GETOPT_H)
# this is temporary for just verification
include(FindOpenSSL)
if (OPENSSL_FOUND)
	check_include_file("openssl/md5.h" WC_OPENSSL_MD5_H)
endif (OPENSSL_FOUND)

if (NOT CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/wisecracker)
else (NOT CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_PREFIX_SAVE ${CMAKE_INSTALL_PREFIX})
	file(TO_CMAKE_PATH ${CMAKE_INSTALL_PREFIX_SAVE} CMAKE_INSTALL_PREFIX)
endif (NOT CMAKE_INSTALL_PREFIX)
include(InstallRequiredSystemLibraries)

find_program(XXD xxd)
if (XXD STREQUAL "XXD-NOTFOUND")
	message(FATAL_ERROR "Please install the commandline tool xxd.")
else (XXD STREQUAL "XXD-NOTFOUND")
	message(STATUS "Found xxd at ${XXD}")
endif (XXD STREQUAL "XXD-NOTFOUND")
