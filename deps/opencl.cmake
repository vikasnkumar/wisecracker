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
### DATE: 21st Dec 2011
########################################
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
if (WIN32)
    set(OPENCL_LDFLAGS ${OPENCL_ROOT}/lib ${OPENCL_ROOT}/lib/Win32)
    set(OPENCL_LIBS OpenCL)
else (WIN32)
    set(OPENCL_LDFLAGS ${OPENCL_ROOT}/lib ${OPENCL_ROOT}/common/lib)
    set(OPENCL_LIBS OpenCL)
endif (WIN32)

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
