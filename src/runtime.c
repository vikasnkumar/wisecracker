/*
Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of Selective Intellect LLC nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * Copyright: 2011. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 21st Dec 2011
 * Software: WiseCracker
 */
#include <wisecracker.h>

static void CALLBACK wc_runtime_pfn_notify(const char *errinfo,
											const void *pvtinfo,
											size_t cb, void *userdata)
{
	WC_ERROR("OpenCL runtime returned error: %s\n", (errinfo) ? errinfo :
			"unknown");
}

static int wc_runtime_platform_info(wc_device_t *dev)
{
#undef LOCAL_PLATFORM_INFO
#define LOCAL_PLATFORM_INFO(TYPE,VAR,PLID) \
do { \
    size_t bufsz = 0; \
    memset(buffer, 0, sizeof(buffer)); \
    if (clGetPlatformInfo(PLID, TYPE, \
                sizeof(buffer), buffer, &bufsz) != CL_SUCCESS) { \
		WC_ERROR("clGetPlatformInfo() Error: failed to get %s.\n", #TYPE); \
        rc = -1; \
        break; \
    } \
    (VAR) = (char *)malloc((bufsz + 1) * sizeof(char)); \
    if ((VAR)) { \
        memcpy((VAR), buffer, bufsz); \
        (VAR)[bufsz] = '\0'; \
        rc = 0; \
    } else { \
		WC_ERROR_OUTOFMEMORY(bufsz + 1); \
        rc = -1; \
        break; \
    } \
} while (0)
    int rc = -1;
    if (!dev)
        return -1;
    do {
        char buffer[1024]; 
		cl_platform_id plid = dev->platform;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_PROFILE, dev->pl_profile, plid);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_VERSION, dev->pl_version, plid);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_NAME, dev->pl_name, plid);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_VENDOR, dev->pl_vendor, plid);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_EXTENSIONS, dev->pl_ext, plid);
        if (rc < 0)
            break;
    } while (0);
#undef LOCAL_PLATFORM_INFO
    return rc;
}

static int wc_runtime_device_info(wc_device_t *dev)
{
	cl_int rc = CL_SUCCESS;
	if (!dev)
		return -1;
	do {
		cl_uint val_uint = 0;
		cl_ulong val_ulong = 0;
		size_t val_sizet = 0;
		val_uint = 0;
		rc = clGetDeviceInfo(dev->id, CL_DEVICE_MAX_COMPUTE_UNITS,
				sizeof(cl_uint), &val_uint, NULL);
		WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);	
		dev->compute_units = val_uint;
		
		val_sizet = 0;
		rc = clGetDeviceInfo(dev->id, CL_DEVICE_MAX_WORK_GROUP_SIZE,
				sizeof(size_t), &val_sizet, NULL);
		WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);	
		dev->workgroup_sz = val_sizet;

		val_uint = 0;
		rc = clGetDeviceInfo(dev->id, CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS,
				sizeof(size_t), &val_uint, NULL);
		WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);
		dev->workitem_dim = val_uint;
		
		dev->workitem_sz = NULL;
		if (dev->workitem_dim > 0) {
			dev->workitem_sz = WC_MALLOC(sizeof(size_t) * dev->workitem_dim);
			if (!dev->workitem_sz) {
				WC_ERROR_OUTOFMEMORY(sizeof(size_t) * dev->workitem_dim);
				rc = -1;
				break;
			}
			rc = clGetDeviceInfo(dev->id, CL_DEVICE_MAX_WORK_ITEM_SIZES,
					sizeof(size_t) * dev->workitem_dim, dev->workitem_sz, NULL);
			if (rc != CL_SUCCESS) {
				WC_FREE(dev->workitem_sz);
				dev->workitem_dim = 0;
			}
			WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);
		}
		
		val_ulong = 0;
		rc = clGetDeviceInfo(dev->id, CL_DEVICE_MAX_MEM_ALLOC_SIZE,
				sizeof(cl_ulong), &val_ulong, NULL);
		WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);
		dev->allocmem_sz = val_ulong;
		
		val_ulong = 0;
		rc = clGetDeviceInfo(dev->id, CL_DEVICE_GLOBAL_MEM_SIZE,
				sizeof(cl_ulong), &val_ulong, NULL);
		WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);
		dev->globalmem_sz = val_ulong;
		
		val_ulong = 0;
		rc = clGetDeviceInfo(dev->id, CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE,
				sizeof(cl_ulong), &val_ulong, NULL);
		WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);
		dev->constmem_sz = val_ulong;
		
		val_ulong = 0;
		rc = clGetDeviceInfo(dev->id, CL_DEVICE_LOCAL_MEM_SIZE,
				sizeof(cl_ulong), &val_ulong, NULL);
		WC_ERROR_OPENCL_BREAK(clGetDeviceInfo, rc);
		dev->localmem_sz = val_ulong;
	} while (0);
	return (rc == CL_SUCCESS) ? 0 : -1;
}

wc_runtime_t *wc_runtime_create(uint32_t flag, uint32_t max_devices)
{
	cl_int rc = CL_SUCCESS;
	cl_platform_id *platforms = NULL;
	cl_device_id *devices = NULL;
	wc_runtime_t *wc = NULL;
	do {
		cl_uint num = 0;
		cl_uint idx = 0;
		cl_device_type devtype = CL_DEVICE_TYPE_DEFAULT;
		char platname[1024];
		if (max_devices == 0) {
			WC_WARN("Max devices parameter given as 0, using 1.\n");
			max_devices = 1;
		}
		// first find the platform ids
		rc = clGetPlatformIDs(0, NULL, &num);
		WC_ERROR_OPENCL_BREAK(clGetPlatformIDs, rc);
		if (num == 0) {
			WC_ERROR("No OpenCL platforms found.\n");
			break;	
		} else {
			WC_INFO("Found %u OpenCL Devices.\n", num);
		}
		platforms = WC_MALLOC(num * sizeof(*platforms));
		if (!platforms) {
			WC_ERROR_OUTOFMEMORY(sizeof(*platforms) * num);
			break;
		}
		memset(platforms, 0, sizeof(*platforms) * num);
		rc = clGetPlatformIDs(num, platforms, NULL);
		WC_ERROR_OPENCL_BREAK(clGetPlatformIDs, rc);
		// find the device that you want
		switch (flag) {
		case WC_DEVICE_CPU:
			devtype = CL_DEVICE_TYPE_CPU;
			WC_INFO("Picking only the CPU based devices.\n");
			break;
		case WC_DEVICE_GPU:
			devtype = CL_DEVICE_TYPE_GPU;
			WC_INFO("Picking only the GPU based devices.\n");
			break;
		case WC_DEVICE_ANY:
			devtype = CL_DEVICE_TYPE_ALL;
			WC_INFO("Picking CPU and/or GPU based devices.\n");
			break;
		default:
			devtype = CL_DEVICE_TYPE_ALL;
			WC_INFO("Picking CPU and/or GPU based devices.\n");
			break;
		}
		wc = WC_MALLOC(sizeof(*wc));
		if (!wc) {
			WC_ERROR_OUTOFMEMORY(sizeof(*wc));
			break;
		}
		memset(wc, 0, sizeof(*wc));
		wc->devices = WC_MALLOC(sizeof(wc_device_t) * max_devices);
		if (!wc->devices) {
			WC_ERROR_OUTOFMEMORY(sizeof(wc_device_t) * max_devices);
			rc = -1;
			break;
		}
		memset(wc->devices, 0, sizeof(wc_device_t) * max_devices);
		wc->device_max = max_devices;
		wc->device_index = 0;
		devices = WC_MALLOC(sizeof(cl_device_id) * max_devices);
		if (!devices) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_device_id) * max_devices);
			rc = -1;
		}
		for (idx = 0; idx < num && wc->device_index < wc->device_max; ++idx) {
			cl_uint devnum = 0;
			cl_uint jdx = 0;
			size_t platnamesz = sizeof(platname);
			memset(platname, 0, platnamesz);
			rc = clGetPlatformInfo(platforms[idx], CL_PLATFORM_NAME, platnamesz,
					platname, &platnamesz);
			WC_ERROR_OPENCL_BREAK(clGetPlatformInfo, rc);
			rc = clGetDeviceIDs(platforms[idx], devtype, 0, NULL, &devnum);
			if (rc == CL_DEVICE_NOT_FOUND || devnum == 0) {
				WC_INFO("No devices found for platform %s\n", platname);
				continue;
			} else {
				WC_ERROR_OPENCL_BREAK(clGetDeviceIDs, rc);
				WC_INFO("Found %u devices for platform %s\n", devnum, platname);
			}
			// find only the number of devices needed
			if (devnum > (wc->device_max - wc->device_index))
				devnum = (wc->device_max - wc->device_index);
			if (devnum == 0)
				break;
			memset(devices, 0, sizeof(cl_device_id) * max_devices);
			// we only want devnum devices
			rc = clGetDeviceIDs(platforms[idx], devtype, devnum, devices,
								&devnum);
			WC_ERROR_OPENCL_BREAK(clGetDeviceIDs, rc);
			for (jdx = 0; jdx < devnum; ++jdx) {
				cl_context_properties props[3];
				wc_device_t *dev = &wc->devices[wc->device_index];
				memset(dev, 0, sizeof(*dev));
				dev->id = devices[jdx];
				dev->platform = platforms[idx];
				dev->type = devtype;
				if (wc_runtime_device_info(dev) < 0)
					continue;
				wc_runtime_platform_info(dev);
				props[0] = CL_CONTEXT_PLATFORM;
				props[1] = (cl_context_properties)dev->platform;
				props[2] = 0;
				dev->context = clCreateContext(props, 1, &dev->id,
								wc_runtime_pfn_notify, NULL, &rc);
				WC_ERROR_OPENCL_BREAK(clCreateContext, rc);
				dev->cmdq = clCreateCommandQueue(dev->context, dev->id,
						CL_QUEUE_PROFILING_ENABLE, &rc);
				WC_ERROR_OPENCL_BREAK(clCreateCommandQueue, rc);
				wc->device_index++;
			}
		}
		if (rc != CL_SUCCESS)
			break;
		if (wc->device_index == 0) {
			WC_ERROR("Unable to successfully find %u devices.\n", max_devices);
			rc = -1;
		}
	} while (0);
	WC_FREE(platforms);
	WC_FREE(devices);
	if (rc != CL_SUCCESS && wc) {
		wc_runtime_destroy(wc);
		wc = NULL;
	}
	return wc;
}

void wc_runtime_destroy(wc_runtime_t *wc)
{
	if (wc) {
		uint32_t idx;
		for (idx = 0; idx < wc->device_index; ++idx) {
			cl_int rc = CL_SUCCESS;
			if (wc->devices[idx].cmdq) {
				rc = clFinish(wc->devices[idx].cmdq);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clFinish, rc);
				rc = clReleaseCommandQueue(wc->devices[idx].cmdq);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clReleaseCommandQueue, rc);
			}
			if (wc->devices[idx].program) {
				rc = clReleaseProgram(wc->devices[idx].program);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clReleaseProgram, rc);
			}
			if (wc->devices[idx].context) {
				rc = clReleaseContext(wc->devices[idx].context);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clReleaseContext, rc);
			}
			WC_FREE(wc->devices[idx].workitem_sz);
			WC_FREE(wc->devices[idx].pl_name);
			WC_FREE(wc->devices[idx].pl_ext);
			WC_FREE(wc->devices[idx].pl_version);
			WC_FREE(wc->devices[idx].pl_vendor);
			WC_FREE(wc->devices[idx].pl_profile);
		}
		WC_FREE(wc->devices);
		memset(wc, 0, sizeof(*wc));
		WC_FREE(wc);
	}
}

void wc_runtime_dump(const wc_runtime_t *wc)
{
	uint32_t idx;
	if (!wc)
		return;
#undef LOCAL_PRINT_UNITS
#define LOCAL_PRINT_UNITS(STR,A) \
do { \
	char *unit_str = NULL; \
	size_t val = 0; \
	if (((A) / (1024 * 1024)) > 1) {\
		unit_str = "MB"; \
		val = (A) / (1024 * 1024); \
	} else if (((A) / 1024) > 1) {\
		unit_str = "KB"; \
		val = (A) / 1024; \
	} else {\
		unit_str = "bytes"; \
		val = (A); \
	} \
	WC_INFO(STR "%lu %s\n", val, unit_str); \
} while (0)

	WC_INFO("No. of devices: %u\n", wc->device_index);
	for (idx = 0; idx < wc->device_index; ++idx) {
		const wc_device_t *dev = &wc->devices[idx];
		WC_INFO("Device Platform Name: %s\n", (dev->pl_name ?
					dev->pl_name : "unknown"));
		WC_INFO("Device Platform Version: %s\n", (dev->pl_version ?
					dev->pl_version : "unknown"));
		WC_INFO("Device Platform Vendor: %s\n", (dev->pl_vendor ?
					dev->pl_vendor : "unknown"));
		WC_INFO("Device Platform Profile: %s\n", (dev->pl_profile ?
					dev->pl_profile : "unknown"));
		WC_INFO("Device Platform Extensions: %s\n", (dev->pl_ext ?
					dev->pl_ext : "unknown"));
		WC_INFO("Device Compute Units: %u\n", dev->compute_units);
		WC_INFO("Device Workgroup size: %lu\n", dev->workgroup_sz);
		WC_INFO("Device Work item dimension: %u\n", dev->workitem_dim);
		if (dev->workitem_sz) {
			cl_uint jdx;
			for (jdx = 0; jdx < dev->workitem_dim; ++jdx)
				WC_INFO("Device Workitem[%u]: %lu\n", jdx, dev->workitem_sz[jdx]);
		}
		LOCAL_PRINT_UNITS("Device Max alloc memory: ", dev->allocmem_sz);
		LOCAL_PRINT_UNITS("Device Max global memory: ", dev->globalmem_sz);
		LOCAL_PRINT_UNITS("Device Max constant memory: ", dev->constmem_sz);
		LOCAL_PRINT_UNITS("Device Max local memory: ", dev->localmem_sz);
	}
#undef LOCAL_PRINT_UNITS
}

static void wc_runtime_program_buildlog(wc_device_t *dev, int verbose)
{
	if (dev) {
		cl_int rc = CL_SUCCESS;
		size_t logsz = 0;
		char *logmsg = NULL;
		rc = clGetProgramBuildInfo(dev->program, dev->id, CL_PROGRAM_BUILD_LOG, 0,
									NULL, &logsz);
		if (rc != CL_SUCCESS) {
			WC_ERROR_OPENCL(clGetProgramBuildInfo, rc);
			return;
		}
		logsz++; // add a char for '\0'
		logmsg = WC_MALLOC(logsz);
		if (!logmsg) {
			WC_ERROR_OUTOFMEMORY(logsz);
			return;
		}
		memset(logmsg, 0, logsz);
		rc = clGetProgramBuildInfo(dev->program, dev->id, CL_PROGRAM_BUILD_LOG,
									logsz, logmsg, &logsz);
		if (rc != CL_SUCCESS) {
			WC_ERROR_OPENCL(clGetProgramBuildInfo, rc);
		} else {
			if (!verbose) {
				if (logsz <= 4) //'\r\n\r\n'
					WC_INFO("Successfully compiled.\n");
				else
					WC_INFO("OpenCL Compiler errors:\n%s\n", logmsg);
			} else {
				WC_INFO("OpenCL Compiler output:\n%s\n", logmsg);
			}
		}
		WC_FREE(logmsg);
	}
}

int wc_runtime_program_load(wc_runtime_t *wc, const char *src, size_t len,
							const char *buildopts, int verbose)
{
	cl_int rc = CL_SUCCESS;
	char *build_options = NULL;
	uint32_t idx;
	if (!wc || !src || len == 0)
		return -1;
	if (wc->device_index < 1) {
		WC_ERROR("No OpenCL devices found.\n");
		return -1;
	}
	if (buildopts) {
		size_t olen = strlen(buildopts) + strlen(WC_OPENCL_OPTS) + 64;
		if (verbose)
			olen += strlen(WC_OPENCL_VERBOSE);
		build_options = WC_MALLOC(olen);
		if (!build_options) {
			WC_ERROR_OUTOFMEMORY(olen);
			return -1;
		} else {
			memset(build_options, 0, olen);
			if (!verbose)
				snprintf(build_options, olen, "%s %s", buildopts, WC_OPENCL_OPTS);
			else
				snprintf(build_options, olen, "%s %s %s", buildopts,
						WC_OPENCL_OPTS, WC_OPENCL_VERBOSE);
		}
	} else {
		size_t olen = strlen(WC_OPENCL_OPTS) + 64;
		if (verbose)
			olen += strlen(WC_OPENCL_VERBOSE);
		build_options = WC_MALLOC(olen);
		if (!build_options) {
			WC_ERROR_OUTOFMEMORY(olen);
			return -1;
		} else {
			memset(build_options, 0, olen);
			if (!verbose)
				snprintf(build_options, olen, "%s", WC_OPENCL_OPTS);
			else
				snprintf(build_options, olen, "%s %s", WC_OPENCL_OPTS,
						WC_OPENCL_VERBOSE);
		}
	}
	WC_INFO("Using build options: %s\n", build_options);
	for (idx = 0; idx < wc->device_index; ++idx) {
		cl_program program;
		struct timeval tv1, tv2;
		wc_device_t *dev = &wc->devices[idx];
		if (dev->program) {
			int err = clReleaseProgram(dev->program);
			if (err != CL_SUCCESS)
				WC_ERROR_OPENCL(clReleaseProgram, err);
		}
		dev->program = (cl_program)0;
		gettimeofday(&tv1, NULL);
		program = clCreateProgramWithSource(dev->context, 1, &src, &len, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateProgramWithSource, rc);
		dev->program = program;
		rc = clBuildProgram(dev->program, 1, &dev->id, build_options,
							NULL, NULL);
		if (rc != CL_SUCCESS) {
			wc_runtime_program_buildlog(dev, 0);
			clReleaseProgram(dev->program);
			dev->program = (cl_program)0;
			WC_ERROR_OPENCL_BREAK(clBuildProgram, rc);
		} else {
			if (verbose)
				wc_runtime_program_buildlog(dev, verbose);
		}
		gettimeofday(&tv2, NULL);
		WC_INFO("Time taken to compile for device(%s) is %lf seconds.\n",
				dev->pl_name, WC_TIME_TAKEN(tv1, tv2));
	}
	WC_FREE(build_options);
	return (rc == CL_SUCCESS) ? 0 : -1;
}

uint8_t wc_runtime_is_usable(const wc_runtime_t *wc)
{
	return (wc && wc->devices && wc->device_index > 0) ? 1 : 0;
}
