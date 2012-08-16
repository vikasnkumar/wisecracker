########################################
### COPYRIGHT: Selective Intellect LLC
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
########################################

configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/wisecracker/config.h @ONLY)
set(CLEAN_FILES md5_cl.h md5_cl.data ${CLEAN_FILES})
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
	"${CLEAN_FILES}")
