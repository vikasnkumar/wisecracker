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

add_executable(wisecrackmd5 md5crack.c)
add_dependencies(wisecrackmd5 md5_cl.h)
target_link_libraries(wisecrackmd5 wisecracker_s)
install(TARGETS wisecrackmd5 RUNTIME DESTINATION bin)

if (USE_OPENSSL)
	add_executable(wctestmd5 md5test.c)
	add_dependencies(wctestmd5 md5_cl.h)
	target_link_libraries(wctestmd5 wisecracker_s ${OPENSSL_LIBRARIES})
	install(TARGETS wctestmd5 RUNTIME DESTINATION bin)
endif (USE_OPENSSL)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
	"${CLEAN_FILES}")
