/*
    Wisecracker: A cryptanalysis framework
    Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
       
   	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.
   
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
   
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
 * Copyright: 2011 - 2012. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 21st Dec 2011
 * Software: WiseCracker
 */
#ifndef __WISECRACKER_RUNTIME_H__
#define __WISECRACKER_RUNTIME_H__

EXTERN_C_BEGIN

typedef struct {
		cl_platform_id id;
		char *name;
		char *extension;
		char *version;
		char *profile;
		char *vendor;
		cl_uint *dev_indices; /* reverse index into the device array */
		cl_uint used_devices; /* number of devices used */
		cl_uint max_devices; /* max number of devices for this platform */
		cl_context context; /* a context is per platform */
} wc_platform_t;

typedef struct {
	cl_device_id id;
	cl_uint pl_index; /* index into the platforms array */
	cl_device_type type;
	cl_uint compute_units;
	size_t workgroup_sz;
	cl_uint workitem_dim;
	size_t *workitem_sz;
	cl_ulong allocmem_sz;
	cl_ulong globalmem_sz;
	cl_ulong constmem_sz;
	cl_ulong localmem_sz;
	cl_command_queue cmdq;
	cl_program program;
} wc_device_t;

typedef struct {
	/*  an array of platforms */
	wc_platform_t *platforms;
	cl_uint platform_max;
	/* an array of devices */
	wc_device_t *devices;
	cl_uint device_max;
} wc_runtime_t;


#define WC_DEVICE_CPU 0x0
#define WC_DEVICE_GPU 0x1
#define WC_DEVICE_ANY 0x2

/* the flag can take values WC_DEVICE_CPU, WC_DEVICE_GPU or WC_DEVICE_ANY
 * Any other value is interpreted as WC_DEVICE_ANY.
 */
WCDLL wc_runtime_t *wc_runtime_create(uint32_t devicetype, uint32_t max_devices);

WCDLL void wc_runtime_destroy(wc_runtime_t *wc);

WCDLL void wc_runtime_dump(const wc_runtime_t *wc);

WCDLL int wc_runtime_program_load(wc_runtime_t *wc, const char *src, size_t len,
							const char *buildopts);

WCDLL uint8_t wc_runtime_is_usable(const wc_runtime_t *wc);
	
EXTERN_C_END

#endif //__WISECRACKER_RUNTIME_H__

