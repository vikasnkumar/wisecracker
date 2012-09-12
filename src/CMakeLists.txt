### Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
### All rights reserved.
### 
### Redistribution and use in source and binary forms, with or without
### modification, are permitted provided that the following conditions are met:
### 
###     * Redistributions of source code must retain the above copyright
###       notice, this list of conditions and the following disclaimer.
### 
###     * Redistributions in binary form must reproduce the above copyright
###       notice, this list of conditions and the following disclaimer in the
###       documentation and/or other materials provided with the distribution.
### 
###     * Neither the name of Selective Intellect LLC nor the
###       names of its contributors may be used to endorse or promote products
###       derived from this software without specific prior written permission.
### 
### THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
### ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
### WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
### DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
### DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
### (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
### LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
### ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
### (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
### SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
### 
########################################
### COPYRIGHT: Selective Intellect LLC
### AUTHOR: Vikas Kumar
### DATE: 25th August 2011
########################################
project(wisecracker C)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# use XXD to convert the default OpenCL files into headers
set(MD5CL md5.cl)
add_custom_target(md5_cl.h ALL
	${XXD} -i < ${CMAKE_CURRENT_SOURCE_DIR}/${MD5CL} > md5_cl.data
	COMMAND ${CMAKE_COMMAND} -E copy_if_different md5_cl.data md5_cl.h
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} VERBATIM)
add_definitions(-DWC_MD5_CL="${MD5CL}")
set(CLEAN_FILES md5_cl.h md5_cl.data ${CLEAN_FILES})

set(UTIL_SRCS utils.c)
if (NOT WC_GETOPT_H)
	set(UTIL_SRCS ${UTIL_SRCS} getopt.c)
endif (NOT WC_GETOPT_H)

add_library(wisecracker_s STATIC runtime.c ${UTIL_SRCS})
target_link_libraries(wisecracker_s ${OPENCL_LIBS})
add_library(wisecracker SHARED runtime.c ${UTIL_SRCS})
target_link_libraries(wisecracker ${OPENCL_LIBS})
set_target_properties(wisecracker PROPERTIES DEFINE_SYMBOL "WC_COMPILING_DLL")
install(TARGETS wisecracker_s ARCHIVE DESTINATION lib)
install(TARGETS wisecracker RUNTIME DESTINATION bin LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)

add_executable(wisecrackmd5 wisecrackmd5.c)
add_dependencies(wisecrackmd5 md5_cl.h)
target_link_libraries(wisecrackmd5 wisecracker_s ${OPENSSL_LIBRARIES})
install(TARGETS wisecrackmd5 RUNTIME DESTINATION bin)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
	"${CLEAN_FILES}")

#add_executable(testmd5 testmd5.c)
#target_link_libraries(testmd5 crypto ${OPENCL_LIBS})

