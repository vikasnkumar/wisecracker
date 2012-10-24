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
	cl_program program; /* a program is per context */
} wc_clplatform_t;

typedef struct {
	/*  an array of platforms */
	wc_clplatform_t *platforms;
	cl_uint platform_max;
	/* an array of devices */
	wc_cldev_t *devices;
	cl_uint device_max;
} wc_opencl_t;

int wc_opencl_init(wc_devtype_t devt, uint32_t max_devices,
					wc_opencl_t *ocl, uint8_t allow_outoforder);

void wc_opencl_finalize(wc_opencl_t *ocl);

void wc_opencl_dump(const wc_opencl_t *ocl);

int wc_opencl_program_load(wc_opencl_t *ocl, const char *src, size_t len,
							const char *buildopts);

uint8_t wc_opencl_is_usable(const wc_opencl_t *ocl);
	
cl_uint wc_opencl_min_device_address_bits(const wc_opencl_t *ocl);

int wc_opencl_flush_cmdq(wc_cldev_t *dev);

int wc_opencl_event_set(cl_event ev);

cl_event wc_opencl_event_create(wc_opencl_t *ocl);

typedef void (CL_CALLBACK * wc_opencl_event_cb_t)(cl_event, cl_int, void *);

int wc_opencl_event_enqueue_wait(wc_cldev_t *dev, cl_event *evptr,
					cl_uint evcount, wc_opencl_event_cb_t evcb, void *cbarg);

int wc_opencl_event_wait(cl_event *evptr, cl_uint evcount);

void wc_opencl_event_release(cl_event);

EXTERN_C_END

#endif //__WISECRACKER_OPENCL_INTERNAL_H__

