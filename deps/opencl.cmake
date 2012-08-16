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
    set(OPENCL_LIBS GL GLU X11 Xmu OpenCL)
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
