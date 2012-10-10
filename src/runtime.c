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
 * Copyright: 2011. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 21st Dec 2011
 * Software: WiseCracker
 */
#include <wisecracker.h>

#ifdef DEBUG
	#define WC_PROFILING_ENABLE CL_QUEUE_PROFILING_ENABLE
#else
	#define WC_PROFILING_ENABLE 0
#endif

static void CL_CALLBACK wc_runtime_pfn_notify(const char *errinfo,
											const void *pvtinfo,
											size_t cb, void *userdata)
{
//	wc_runtime_t *wc = (wc_runtime_t *)userdata;
	WC_ERROR("OpenCL runtime returned error: %s\n", (errinfo) ? errinfo :
			"unknown");
}

static int wc_runtime_platform_info(wc_platform_t *plat)
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
    (VAR) = (char *)WC_MALLOC((bufsz + 1) * sizeof(char)); \
    if ((VAR)) { \
        memcpy((VAR), buffer, bufsz); \
        (VAR)[bufsz] = '\0'; \
        rc = 0; \
    } else { \
		WC_ERROR_OUTOFMEMORY(bufsz + 1); \
        rc = CL_OUT_OF_HOST_MEMORY; \
        break; \
    } \
} while (0)
    int rc = -1;
    if (!plat)
        return -1;
    do {
        char buffer[1024]; 
        LOCAL_PLATFORM_INFO(CL_PLATFORM_PROFILE, plat->profile, plat->id);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_VERSION, plat->version, plat->id);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_NAME, plat->name, plat->id);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_VENDOR, plat->vendor, plat->id);
        if (rc < 0)
            break;
        LOCAL_PLATFORM_INFO(CL_PLATFORM_EXTENSIONS, plat->extension, plat->id);
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
				rc = CL_OUT_OF_HOST_MEMORY;
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

wc_runtime_t *wc_runtime_create(uint32_t flag, uint32_t max_devices,
								uint8_t allow_outoforder)
{
	cl_int rc = CL_SUCCESS;
	cl_platform_id *plids = NULL;
	cl_device_id *devids = NULL;
	wc_runtime_t *wc = NULL;
	do {
		cl_uint num = 0;
		cl_uint idx = 0;
		cl_uint total_devnum = 0;
		cl_uint dev_idx = 0;
		cl_device_type devtype = CL_DEVICE_TYPE_DEFAULT;
		// first find the platform ids
		rc = clGetPlatformIDs(0, NULL, &num);
		WC_ERROR_OPENCL_BREAK(clGetPlatformIDs, rc);
		if (num == 0) {
			WC_ERROR("No OpenCL platforms found.\n");
			break;	
		} else {
			WC_INFO("Found %u OpenCL Platforms.\n", num);
		}
		plids = WC_MALLOC(num * sizeof(*plids));
		if (!plids) {
			WC_ERROR_OUTOFMEMORY(sizeof(*plids) * num);
			rc = CL_OUT_OF_HOST_MEMORY;
			break;
		}
		memset(plids, 0, sizeof(*plids) * num);
		rc = clGetPlatformIDs(num, plids, NULL);
		WC_ERROR_OPENCL_BREAK(clGetPlatformIDs, rc);
		// find the device that you want
		switch (flag) {
		case WC_DEVICE_CPU:
			devtype = CL_DEVICE_TYPE_CPU;
			WC_INFO("Picking only the CPU based devices.\n");
			WC_DEBUG("Max devices for CPU has to be set to 1.\n");
			max_devices = 1;
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
			rc = CL_OUT_OF_HOST_MEMORY;
			break;
		}
		memset(wc, 0, sizeof(*wc));
		wc->platforms = WC_MALLOC(sizeof(wc_platform_t) * num);
		if (!wc->platforms) {
			WC_ERROR_OUTOFMEMORY(sizeof(wc_platform_t) * num);
			rc = CL_OUT_OF_HOST_MEMORY;
			break;
		}
		memset(wc->platforms, 0, sizeof(wc_platform_t) * num);
		wc->platform_max = num;
		// set up the platforms first
		total_devnum = 0;
		for (idx = 0; idx < num; ++idx) {
			cl_uint devnum = 0;
			wc_platform_t *plat = &wc->platforms[idx];
			plat->id = plids[idx];
			if ((rc = wc_runtime_platform_info(plat) < 0))
				break;
			// get the number of devices on this platform
			// if the device type doesn't match then obviously we ignore this
			// platform
			rc = clGetDeviceIDs(plat->id, devtype, 0, NULL, &devnum);
			if (rc == CL_DEVICE_NOT_FOUND || devnum == 0) {
				WC_INFO("No devices found for platform %s\n", plat->name);
				plat->max_devices = 0;
				rc = CL_SUCCESS;
				continue;
			} else {
				WC_ERROR_OPENCL_BREAK(clGetDeviceIDs, rc);
				WC_INFO("Found %u devices for platform %s\n", devnum,
						plat->name);
				total_devnum += devnum;
				plat->max_devices = devnum;
				plat->dev_indices = WC_MALLOC(sizeof(*plat->dev_indices) *
												plat->max_devices);
				if (!plat->dev_indices) {
					WC_ERROR_OUTOFMEMORY(sizeof(*plat->dev_indices) *
										plat->max_devices);
					rc = CL_OUT_OF_HOST_MEMORY;
					break;
				}
				memset(plat->dev_indices, 0, sizeof(*plat->dev_indices) *
										plat->max_devices);
			}
		}
		if (rc < 0)
			break;
		if (max_devices == 0) {
			max_devices = total_devnum;
			WC_INFO("Using the maximum %u devices.\n", max_devices);
		}
		if (max_devices > total_devnum) {
			WC_WARN("Requested %u devices but only %u exist. Adjusting.\n",
					max_devices, total_devnum);
			max_devices = total_devnum;
		}
		// we collect the device IDs for all platforms into this array
		// we reuse the array per platform, and this array is just large enough
		// to hold all devices but is not used in that way
		devids = WC_MALLOC(sizeof(cl_device_id) * total_devnum);
		if (!devids) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_device_id) * total_devnum);
			rc = CL_OUT_OF_HOST_MEMORY;
			break;
		}
		// now allocate the device structures
		wc->devices = WC_MALLOC(sizeof(wc_device_t) * max_devices);
		if (!wc->devices) {
			WC_ERROR_OUTOFMEMORY(sizeof(wc_device_t) * max_devices);
			rc = CL_OUT_OF_HOST_MEMORY;
			break;
		}
		memset(wc->devices, 0, sizeof(wc_device_t) * max_devices);
		wc->device_max = max_devices;
		dev_idx = 0;
		for (idx = 0; idx < wc->platform_max; ++idx) {
			cl_uint devnum = 0;
			cl_uint jdx = 0;
			cl_context_properties props[3];
			wc_platform_t *plat = &wc->platforms[idx];
			// let's reuse the previously stored value
			if (plat->max_devices == 0)
				continue;
			devnum = plat->max_devices;
			// we check if the number of devices requested has been hit or not
			if (devnum > (wc->device_max - dev_idx))
				devnum = wc->device_max - dev_idx;
			if (devnum == 0)
				break;
			memset(devids, 0, sizeof(cl_device_id) * total_devnum);
			// we only want devnum devices
			rc = clGetDeviceIDs(plids[idx], devtype, devnum, devids, NULL);
			WC_ERROR_OPENCL_BREAK(clGetDeviceIDs, rc);
			// create context for all devices for this platform
			// NOTE: we cannot create multiple platform context since vendors
			// except AMD as of 2nd Oct 2012 don't support that.
			props[0] = CL_CONTEXT_PLATFORM;
			props[1] = (cl_context_properties)plat->id;
			props[2] = 0;
			plat->context = clCreateContext(props, devnum, devids,
								wc_runtime_pfn_notify, (void *)wc, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateContext, rc);
			// store the device information into its structure
			plat->used_devices = 0; // jdx need not be equal to used_devices
			for (jdx = 0; jdx < devnum && dev_idx < wc->device_max &&
						plat->used_devices < plat->max_devices; ++jdx) {
				wc_device_t *dev = &wc->devices[dev_idx];
				cl_command_queue_properties props = WC_PROFILING_ENABLE;
				memset(dev, 0, sizeof(*dev));
				dev->id = devids[jdx];
				dev->pl_index = idx;
				dev->type = devtype;
				if (wc_runtime_device_info(dev) < 0)
					continue;
				if (allow_outoforder)
					props |= CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE;
				// we create a command queue per device
				dev->cmdq = clCreateCommandQueue(plat->context, dev->id, props,
												&rc);
				WC_ERROR_OPENCL_BREAK(clCreateCommandQueue, rc);
				plat->dev_indices[plat->used_devices++] = dev_idx;
				dev_idx++;
			}
		}
		if (rc != CL_SUCCESS)
			break;
		if (dev_idx == 0) {
			WC_ERROR("Unable to successfully find %u devices.\n", max_devices);
			rc = -1;
		}
	} while (0);
	WC_FREE(plids);
	WC_FREE(devids);
	if (rc != CL_SUCCESS && wc) {
		wc_runtime_destroy(wc);
		wc = NULL;
	}
	return wc;
}

void wc_runtime_destroy(wc_runtime_t *wc)
{
	if (wc) {
		cl_uint idx;
		for (idx = 0; idx < wc->device_max; ++idx) {
			cl_int rc = CL_SUCCESS;
			if (wc->devices[idx].cmdq) {
				rc = clFinish(wc->devices[idx].cmdq);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clFinish, rc);
				rc = clReleaseCommandQueue(wc->devices[idx].cmdq);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clReleaseCommandQueue, rc);
			}
			WC_FREE(wc->devices[idx].workitem_sz);
		}
		for (idx = 0; idx < wc->platform_max; ++idx) {
			cl_int rc = CL_SUCCESS;
			if (wc->platforms[idx].program) {
				rc = clReleaseProgram(wc->platforms[idx].program);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clReleaseProgram, rc);
			}
			if (wc->platforms[idx].context) {
				rc = clReleaseContext(wc->platforms[idx].context);
				if (rc != CL_SUCCESS)
					WC_ERROR_OPENCL(clReleaseContext, rc);
			}
			WC_FREE(wc->platforms[idx].name);
			WC_FREE(wc->platforms[idx].extension);
			WC_FREE(wc->platforms[idx].version);
			WC_FREE(wc->platforms[idx].vendor);
			WC_FREE(wc->platforms[idx].profile);
			WC_FREE(wc->platforms[idx].dev_indices);
		}
		WC_FREE(wc->devices);
		WC_FREE(wc->platforms);
		memset(wc, 0, sizeof(*wc));
		WC_FREE(wc);
	}
}

void wc_runtime_dump(const wc_runtime_t *wc)
{
	cl_uint idx;
	if (!wc)
		return;
#undef LOCAL_PRINT_UNITS
#define LOCAL_PRINT_UNITS(STR,JDX,A) \
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
	WC_INFO(STR "%lu %s\n", (JDX), val, unit_str); \
} while (0)

	WC_INFO("Total No. of platforms: %u\n", wc->platform_max);
	WC_INFO("Total No. of devices: %u\n", wc->device_max);
	for (idx = 0; idx < wc->platform_max; ++idx) {
		cl_uint jdx;
		const wc_platform_t *plat = &wc->platforms[idx];
		WC_INFO("Platform Name: %s\n", (plat->name ?
					plat->name : "unknown"));
		WC_INFO("Platform Version: %s\n", (plat->version ?
					plat->version : "unknown"));
		WC_INFO("Platform Vendor: %s\n", (plat->vendor ?
					plat->vendor : "unknown"));
		WC_INFO("Platform Profile: %s\n", (plat->profile ?
					plat->profile : "unknown"));
		WC_INFO("Platform Extensions: %s\n", (plat->extension ?
					plat->extension : "unknown"));
		WC_INFO("Platform Max Device Count: %u\n", plat->max_devices);
		for (jdx = 0; jdx < plat->used_devices; ++jdx) {
			cl_uint devidx = plat->dev_indices[jdx];
			const wc_device_t *dev = NULL;
			if (devidx >= wc->device_max)
				continue;
			dev = &wc->devices[devidx];
			WC_INFO("Device[%u] Compute Units: %u\n", devidx,
					dev->compute_units);
			WC_INFO("Device[%u] Workgroup size: %lu\n", devidx,
					dev->workgroup_sz);
			WC_INFO("Device[%u] Work item dimension: %u\n", devidx,
					dev->workitem_dim);
			if (dev->workitem_sz) {
				cl_uint kdx;
				for (kdx = 0; kdx < dev->workitem_dim; ++kdx)
					WC_INFO("Device[%u] Workitem[%u]: %lu\n", devidx, kdx,
							dev->workitem_sz[kdx]);
			}
			LOCAL_PRINT_UNITS("Device[%u] Max alloc memory: ", devidx,
								dev->allocmem_sz);
			LOCAL_PRINT_UNITS("Device[%u] Max global memory: ", devidx,
								dev->globalmem_sz);
			LOCAL_PRINT_UNITS("Device[%u] Max constant memory: ", devidx,
								dev->constmem_sz);
			LOCAL_PRINT_UNITS("Device[%u] Max local memory: ", devidx,
								dev->localmem_sz);
		}
	}
#undef LOCAL_PRINT_UNITS
}

static void wc_runtime_program_buildlog(cl_program program, cl_device_id devid,
										const char *plname)
{
	if (program && devid) {
		cl_int rc = CL_SUCCESS;
		size_t logsz = 0;
		char *logmsg = NULL;
		cl_build_status bs;
		rc = clGetProgramBuildInfo(program, devid, CL_PROGRAM_BUILD_STATUS,
						sizeof(cl_build_status), &bs, NULL);
		if (rc != CL_SUCCESS) {
			WC_ERROR_OPENCL(clGetProgramBuildInfo, rc);
			return;
		}
		if (bs == CL_BUILD_SUCCESS) {
			WC_DEBUG("Program build was a success for a device on %s.\n",
					plname);
			return;
		} else if (bs == CL_BUILD_ERROR) {
			WC_ERROR("Program build errored out.\n");
		} else {
			WC_WARN("The build hasn't been invoked or is in progress.\n");
			return;
		}
		rc = clGetProgramBuildInfo(program, devid, CL_PROGRAM_BUILD_LOG, 0,
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
		rc = clGetProgramBuildInfo(program, devid, CL_PROGRAM_BUILD_LOG, logsz,
									logmsg, &logsz);
		if (rc != CL_SUCCESS) {
			WC_ERROR_OPENCL(clGetProgramBuildInfo, rc);
		} else {
			WC_INFO("OpenCL Compiler output:\n%s\n", logmsg);
		}
		WC_FREE(logmsg);
	}
}

//XXX: we could in the future have buildopts per device type
int wc_runtime_program_load(wc_runtime_t *wc, const char *src, size_t len,
							const char *buildopts)
{
	cl_int rc = CL_SUCCESS;
	char *build_options = NULL;
	cl_device_id *devids = NULL;
	cl_uint idx;
	if (!src || len == 0) {
		WC_DEBUG("invalid function parameters.\n");
		return -1;
	}
	if (!wc_runtime_is_usable(wc)) {
		WC_ERROR("wisecracker runtime is not usable.\n");
		return -1;
	}
	if (buildopts) {
		size_t olen = strlen(buildopts) + strlen(WC_OPENCL_OPTS) + 64;
		build_options = WC_MALLOC(olen);
		if (!build_options) {
			WC_ERROR_OUTOFMEMORY(olen);
			return -1;
		} else {
			memset(build_options, 0, olen);
			snprintf(build_options, olen, "%s %s", buildopts, WC_OPENCL_OPTS);
		}
	} else {
		size_t olen = strlen(WC_OPENCL_OPTS) + 64;
		build_options = WC_MALLOC(olen);
		if (!build_options) {
			WC_ERROR_OUTOFMEMORY(olen);
			return -1;
		} else {
			memset(build_options, 0, olen);
			snprintf(build_options, olen, "%s", WC_OPENCL_OPTS);
		}
	}
	WC_INFO("Using build options: %s\n", build_options);
	// allocate a large array for holding device ids
	// the max size of this array is the total number of devices
	// but per platform a smaller size might be needed
	devids = WC_MALLOC(sizeof(cl_device_id) * wc->device_max);
	if (!devids) {
		WC_ERROR_OUTOFMEMORY(sizeof(cl_device_id) * wc->device_max);
		return -1;
	}
	// a program object is per context
	// so we build the program object per platform first
	// then compile it with all the devices
	for (idx = 0; idx < wc->platform_max; ++idx) {
		cl_program program = (cl_program)0;
		struct timeval tv1, tv2;
		cl_uint devnum = 0;
		cl_uint jdx;
		wc_platform_t *plat = &wc->platforms[idx];
		if (plat->used_devices == 0) {
			WC_DEBUG("Platform %s has no devices.\n", plat->name);
			continue;
		}
		if (plat->program) {
			int err = clReleaseProgram(plat->program);
			if (err != CL_SUCCESS)
				WC_ERROR_OPENCL(clReleaseProgram, err);
			WC_DEBUG("Releasing an earlier program.\n");
		}
		plat->program = (cl_program)0;
		wc_util_timeofday(&tv1);
		program = clCreateProgramWithSource(plat->context, 1, &src, &len, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateProgramWithSource, rc);
		// ok let's collect all the device ids into an array
		memset(devids, 0, sizeof(cl_device_id) * wc->device_max);
		devnum = 0;
		for (jdx = 0; jdx < plat->used_devices; ++jdx) {
			cl_uint devidx = plat->dev_indices[jdx];
			if (devidx >= wc->device_max) {
				WC_WARN("Invalid device index %u on platform %s\n", devidx,
						plat->name);
				continue;
			}
			devids[devnum++] = wc->devices[devidx].id;
		}
		// ok we have devnum devices and all the device ids in devids
		// let's build the program per platform
		rc = clBuildProgram(program, devnum, devids, build_options,
							NULL, NULL);
		if (rc != CL_SUCCESS) {
			for (jdx = 0; jdx < devnum; ++jdx)
				wc_runtime_program_buildlog(program, devids[jdx], plat->name);
			clReleaseProgram(program);
			plat->program = (cl_program)0;
			WC_ERROR_OPENCL_BREAK(clBuildProgram, rc);
		} else {
			for (jdx = 0; jdx < devnum; ++jdx)
				wc_runtime_program_buildlog(program, devids[jdx], plat->name);
			plat->program = program;
		}
		wc_util_timeofday(&tv2);
		WC_INFO("Time taken to compile for device(%s) is %lf seconds.\n",
				plat->name, WC_TIME_TAKEN(tv1, tv2));
	}
	WC_FREE(build_options);
	WC_FREE(devids);
	return (rc == CL_SUCCESS) ? 0 : -1;
}

uint8_t wc_runtime_is_usable(const wc_runtime_t *wc)
{
	return (wc && wc->devices && wc->device_max > 0 && wc->platforms &&
			wc->platform_max > 0) ? 1 : 0;
}
