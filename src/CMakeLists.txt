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
### DATE: 25th August 2011
#########################################################################
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

