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
### COPYRIGHT: 2011-2012 Selective Intellect LLC. All Rights Reserved
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
### SOFTWARE: Wisecracker 
#########################################################################

configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/wisecracker/config.h @ONLY)
set(CLEAN_FILES md5_cl.h md5_cl.data ${CLEAN_FILES})
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
	"${CLEAN_FILES}")
install(DIRECTORY wisecracker/ DESTINATION include/wisecracker FILES_MATCHING
	PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wisecracker/config.h DESTINATION
	include/wisecracker)
install(FILES wisecracker.h DESTINATION include)
