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
#ifndef __WISECRACKER_OPENCL_INTERNAL_H__
#define __WISECRACKER_OPENCL_INTERNAL_H__

EXTERN_C_BEGIN

typedef struct {
	/*  an array of platforms */
	wc_platform_t *platforms;
	cl_uint platform_max;
	/* an array of devices */
	wc_device_t *devices;
	cl_uint device_max;
} wc_opencl_t;

int wc_opencl_init(wc_devtype_t devt, uint32_t max_devices,
							wc_opencl_t *rt);

void wc_opencl_finalize(wc_opencl_t *rt);

void wc_opencl_dump(const wc_opencl_t *rt);

int wc_opencl_program_load(wc_opencl_t *wc, const char *src, size_t len,
							const char *buildopts);

uint8_t wc_opencl_is_usable(const wc_opencl_t *wc);
	
cl_uint wc_opencl_min_device_address_bits(const wc_opencl_t *wc);

EXTERN_C_END

#endif //__WISECRACKER_OPENCL_INTERNAL_H__

