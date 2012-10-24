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
### DATE: 11th Oct 2012
#########################################################################
if (USE_MPI)
	include(FindMPI)
	if (MPI_FOUND)
		set(CMAKE_REQUIRED_INCLUDES_SAVE ${CMAKE_REQUIRED_INCLUDES})
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES}
			${MPI_INCLUDE_PATH})
		set(CMAKE_REQUIRED_FLAGS_SAVE ${CMAKE_REQUIRED_FLAGS})
		set(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS} ${MPI_COMPILE_FLAGS})
		check_include_file("mpi.h" WC_MPI_H)
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_SAVE})
		set(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS_SAVE})
		include_directories(${MPI_INCLUDE_PATH})
	else (MPI_FOUND)
		set(USE_MPI OFF)
		message(STATUS "MPI not found for this platform. Disabling MPI")
	endif (MPI_FOUND)
endif (USE_MPI)
