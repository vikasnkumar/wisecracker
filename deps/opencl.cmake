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
if (APPLE)
	check_include_file("OpenCL/opencl.h" WC_OPENCL_H)
	find_library(OPENCL_LIBS OpenCL)
	if (OPENCL_LIBS STREQUAL "OPENCL_LIBS-NOTFOUND")
		message(FATAL_ERROR "OpenCL Framework is not found.")
	endif (OPENCL_LIBS STREQUAL "OPENCL_LIBS-NOTFOUND")
else (APPLE)
	if (NOT OPENCL_ROOT)
		set(OPENCL_ROOT $ENV{OPENCL_ROOT})
		message(STATUS "Using OPENCL from $ENV{OPENCL_ROOT}")
	endif (NOT OPENCL_ROOT)

	if (NOT OPENCL_ROOT)
		message(FATAL_ERROR "Please set the CMake variable or environment "
			"variable OPENCL_ROOT to point to the OpenCL installation")
	endif (NOT OPENCL_ROOT)
	set(OPENCL_INCLUDES
		${OPENCL_ROOT}/include
		${OPENCL_ROOT}/inc
		${OPENCL_ROOT}/common/include
		${OPENCL_ROOT}/common/inc
		)
	set(OPENCL_LDFLAGS ${OPENCL_ROOT}/lib ${OPENCL_ROOT}/lib64
		${OPENCL_ROOT}/common/lib)
	set(OPENCL_LIBS OpenCL)

	set(CMAKE_REQUIRED_INCLUDES_SAVE ${CMAKE_REQUIRED_INCLUDES})
	set(CMAKE_REQUIRED_INCLUDES ${OPENCL_INCLUDES})
	check_include_file("CL/opencl.h" WC_OPENCL_H)
	set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_SAVE})

	if (WC_OPENCL_H)
		include_directories(${OPENCL_INCLUDES})
		link_directories(${OPENCL_LDFLAGS})
	else (WC_OPENCL_H)
		message(FATAL_ERROR "OpenCL is not found. Please set OPENCL_ROOT variable "
			"to point correctly to the OpenCL installation folder.")
	endif (WC_OPENCL_H)
endif (APPLE)
