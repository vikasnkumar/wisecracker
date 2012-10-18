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
 * Date: 16th Oct 2012
 * Software: WiseCracker
 */
#include <wisecracker.h>

#include "internal_mpi.h"
#include "internal_opencl.h"

struct wc_executor_details {
	int peer_count;
	int peer_id;
	uint8_t mpi_initialized;
	wc_exec_callbacks_t cbs;
	uint8_t callbacks_set;
	wc_opencl_t ocl;
	uint8_t ocl_initialized;
	char *code;
	size_t codelen;
	char *buildopts;
	uint64_t num_tasks;
	wc_data_t global;
};

wc_exec_t *wc_executor_init(int *argc, char ***argv)
{
	int rc = 0;
	wc_exec_t *wc = NULL;

	do {
		wc = WC_MALLOC(sizeof(wc_exec_t));
		if (!wc) {
			WC_ERROR_OUTOFMEMORY(sizeof(wc_exec_t));
			wc = NULL;
			break;
		}
		// this memset is necessary
		memset(wc, 0, sizeof(wc_exec_t));
		rc = wc_mpi_init(argc, argv);
		if (rc != 0)
			break;
		wc->mpi_initialized = 1;
		wc->peer_count = wc_mpi_peer_count();
		if (wc->peer_count < 0) {
			rc = -1;
			break;
		}
		wc->peer_id = wc_mpi_peer_id();
		if (wc->peer_id < 0) {
			rc = -1;
			break;
		}
		wc->ocl_initialized = 0;
		wc->callbacks_set = 0;
		wc->cbs.user = NULL;
		wc->cbs.max_devices = 0;
		wc->cbs.device_type = WC_DEVTYPE_ANY;
	} while (0);
	if (rc < 0) {
		if (wc && wc->mpi_initialized) {
			wc_mpi_abort(-1);
			wc->mpi_initialized = 0;
		}
		WC_FREE(wc);
	}
	return wc;
}

void wc_executor_destroy(wc_exec_t *wc)
{
	if (wc) {
		int rc = 0;
		if (wc->ocl_initialized) {
			wc_opencl_finalize(&wc->ocl);
			wc->ocl_initialized = 0;
		}
		WC_FREE(wc->global.ptr);
		wc->global.len = 0;
		WC_FREE(wc->code);
		WC_FREE(wc->buildopts);
		wc->codelen = 0;
		wc->num_tasks = 0;
		if (wc->mpi_initialized) {
			rc = wc_mpi_finalize();
			if (rc != 0) {
				WC_WARN("MPI Finalize error.\n");
			}
			wc->mpi_initialized = 0;
		}
		memset(wc, 0, sizeof(*wc));
		WC_FREE(wc);
	}
}

int wc_executor_peer_count(const wc_exec_t *wc)
{
	return (wc) ? wc->peer_count : WC_EXE_ERR_INVALID_PARAMETER;
}

int wc_executor_peer_id(const wc_exec_t *wc)
{
	return (wc) ? wc->peer_id : WC_EXE_ERR_INVALID_PARAMETER;
}

wc_err_t wc_executor_setup(wc_exec_t *wc, const wc_exec_callbacks_t *cbs)
{
	if (wc && cbs) {
		// verify if the required callbacks are present
		if (!cbs->get_code || !cbs->get_num_tasks) {
			WC_ERROR("Wisecracker needs the get_code, get_num_tasks and"
					" other callbacks.\n");
			wc->callbacks_set = 0;
		} else {
			uint32_t data[2];
			wc_devtype_t devtype;
			uint32_t maxdevs = 0;
			data[0] = (uint32_t)cbs->device_type;
			data[1] = cbs->max_devices;
			if (wc->mpi_initialized) {
				int rc = wc_mpi_broadcast(data, 2, MPI_INT, 0);
				if (rc < 0) {
					WC_ERROR("Unable to share the device type and max devices."
							" MPI Error: %d\n", rc);
					return WC_EXE_ERR_MPI;
				}
			}
			devtype = (wc_devtype_t)data[0];
			maxdevs = data[1];
			// ok we were initialized. let's check if the device-type is same
			// and max-devices is same too
			if (wc->ocl_initialized) {
				if (wc->cbs.device_type == devtype &&
					wc->cbs.max_devices == maxdevs) {
					// do nothing
				} else {
					// finalize it to be reinitialized with a different set of
					// devices and device types
					wc_opencl_finalize(&wc->ocl);
					wc->ocl_initialized = 0;
					WC_DEBUG("Finalizing OpenCL to reinitialize again since"
							" device count and type are changing\n");
				}
			}
			if (!wc->ocl_initialized) {
				if (wc_opencl_init(devtype, maxdevs, &wc->ocl, 0) < 0) {
					WC_ERROR("Failed to create local runtime on system\n");
					return WC_EXE_ERR_OPENCL;
				}
			}
			wc->ocl_initialized = 1;
			// copy the pointers into an internal structure
			memcpy(&(wc->cbs), cbs, sizeof(*cbs));
			// override the values with the received values
			wc->cbs.device_type = devtype;
			wc->cbs.max_devices = maxdevs;
			wc->callbacks_set = 1;
			return WC_EXE_OK;
		}
	}
	return WC_EXE_ERR_INVALID_PARAMETER;
}

enum {
	WC_EXECSTATE_NOT_STARTED = 0,
	WC_EXECSTATE_OPENCL_INITED,
	WC_EXECSTATE_STARTED,
	WC_EXECSTATE_GOT_CODE,
	WC_EXECSTATE_GOT_BUILDOPTS,
	WC_EXECSTATE_COMPILED_CODE,
	WC_EXECSTATE_GOT_NUMTASKS,
	WC_EXECSTATE_GOT_GLOBALDATA,
	WC_EXECSTATE_FINISHED
};

static wc_err_t wc_executor_pre_run(wc_exec_t *wc, int *stateptr)
{
	int current_state = WC_EXECSTATE_NOT_STARTED;
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		current_state = WC_EXECSTATE_NOT_STARTED;
		if (!wc->callbacks_set) {
			WC_ERROR("Callbacks not set for executor.\n");
			rc = WC_EXE_ERR_MISSING_CALLBACK;
			break;
		}
		if (!wc->ocl_initialized) {
			if (wc_opencl_init(wc->cbs.device_type, wc->cbs.max_devices,
						&wc->ocl, 0) < 0) {
				WC_ERROR("Failed to create local runtime on system\n");
				rc = WC_EXE_ERR_OPENCL;
				break;
			}
			wc->ocl_initialized = 1;
		}
		current_state = WC_EXECSTATE_OPENCL_INITED;
		if (!wc_opencl_is_usable(&wc->ocl)) {
			WC_ERROR("OpenCL internal runtime is not usable\n");
			rc = WC_EXE_ERR_BAD_STATE;
			break;
		}
		// call the on_start event
		if (wc->cbs.on_start) {
			rc = wc->cbs.on_start(wc, wc->cbs.user);
			if (rc != WC_EXE_OK) {
				WC_ERROR("Error in on_start callback: %d\n", rc);
				break;
			}
		}
		current_state = WC_EXECSTATE_STARTED;
		// call the get_code function to retrieve the code
		if (!wc->cbs.get_code) {
			WC_ERROR("The get_code callback is missing\n");
			rc = WC_EXE_ERR_MISSING_CALLBACK;
			break;
		} else {
			wc->codelen = 0;
			// clear the code previously loaded
			WC_FREE(wc->code);
			wc->code = wc->cbs.get_code(wc, wc->cbs.user, &wc->codelen);
			if (!wc->code || wc->codelen == 0) {
				WC_ERROR("Error in get_code callback: %d\n", rc);
				break;	
			}
		}
		current_state = WC_EXECSTATE_GOT_CODE;
		// call the build_opts function to retrieve the build options
		if (wc->cbs.get_build_options) {
			WC_FREE(wc->buildopts); // clear the previous loaded options
			wc->buildopts = wc->cbs.get_build_options(wc, wc->cbs.user);
			if (!wc->buildopts) {
				WC_WARN("Build options returned was NULL.\n");
			}
		}
		current_state = WC_EXECSTATE_GOT_BUILDOPTS;
		// ok compile the code now
		if (wc_opencl_program_load(&wc->ocl, wc->code, wc->codelen,
									wc->buildopts) < 0) {
			WC_ERROR("Unable to compile OpenCL code.\n");
			rc = WC_EXE_ERR_OPENCL;
			if (wc->cbs.on_code_compile)
				wc->cbs.on_code_compile(wc, wc->cbs.user, 0);
			break;
		}
		if (wc->cbs.on_code_compile)
			wc->cbs.on_code_compile(wc, wc->cbs.user, 1);
		current_state = WC_EXECSTATE_COMPILED_CODE;
	} while (0);
	if (stateptr)
		*stateptr = current_state;
	return rc;
}

static wc_err_t wc_executor_post_run(wc_exec_t *wc, int *stateptr)
{
	wc_err_t rc = WC_EXE_OK;
	if (!stateptr || !wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	// free the global data
	WC_FREE(wc->global.ptr);
	wc->global.len = 0;
	// call the on_finish event
	if (*stateptr != WC_EXECSTATE_NOT_STARTED && wc->cbs.on_finish) {
		rc = wc->cbs.on_finish(wc, wc->cbs.user);
		if (rc != WC_EXE_OK) {
			WC_ERROR("Error in on_finish callback: %d\n", rc);
		}
		*stateptr = WC_EXECSTATE_FINISHED;
	}
	return rc;
}

static wc_err_t wc_executor_master_run(wc_exec_t *wc, int *stateptr)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc || !stateptr)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		// get task decomposition
		// TODO: we can add another callback to retrieve a more detailed
		// decomposition, but not yet
		if (!wc->cbs.get_num_tasks) {
			WC_ERROR("The get_num_tasks callback is missing\n");
			rc = WC_EXE_ERR_MISSING_CALLBACK;
			break;
		} else {
			wc->num_tasks = wc->cbs.get_num_tasks(wc, wc->cbs.user);
			if (wc->num_tasks == 0) {
				WC_ERROR("Task size cannot be 0.\n");
				rc = WC_EXE_ERR_INVALID_VALUE;
				break;
			}
			WC_DEBUG("No of Tasks: %lu\n", wc->num_tasks);
		}
		*stateptr = WC_EXECSTATE_GOT_NUMTASKS;
		//TODO: exchange the wc_runtime_t device information across the systems
		if (wc->cbs.get_global_data) {
			wc_data_t wcd = { 0 };
			rc = wc->cbs.get_global_data(wc, wc->cbs.user, &wcd);
			if (rc != WC_EXE_OK) {
				WC_ERROR("Error retrieving global data: %d\n", rc);
				break;
			}
			wc->global.ptr = wcd.ptr;
			wc->global.len = wcd.len;
		}
		*stateptr = WC_EXECSTATE_GOT_GLOBALDATA;
		//TODO: send the global data across

		// XXX: Steps for invocation
		// collect total number of tasks on the master, send to slaves later
		// collect per task data on the master, send to slaves later
		// collect global data on the master, send to slaves later
		// process kernels on each system
		// retrieve data for each kernel output
		// send to master for aggregation
	} while (0);
	return rc;
}

static wc_err_t wc_executor_slave_run(wc_exec_t *wc, int *stateptr)
{
	// TODO: receive the global data here
	return WC_EXE_OK;
}

wc_err_t wc_executor_run(wc_exec_t *wc, long timeout)
{
	int current_state;
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		cl_uint idx;
		current_state = WC_EXECSTATE_NOT_STARTED;
		rc = wc_executor_pre_run(wc, &current_state);
		if (rc != WC_EXE_OK)
			break;
		if (wc->peer_id == 0) {
			rc = wc_executor_master_run(wc, &current_state);
		} else {
			rc = wc_executor_slave_run(wc, &current_state);
		}
		if (rc != WC_EXE_OK)
			break;
		if (!wc_opencl_is_usable(&wc->ocl)) {
			WC_ERROR("OpenCL internal runtime is not usable\n");
			rc = WC_EXE_ERR_BAD_STATE;
			break;
		}
		// ok let's invoke the device start functions
		if (wc->cbs.on_device_start) {
			for (idx = 0; idx < wc->ocl.device_max; ++idx) {
				wc_cldev_t *wcd = &(wc->ocl.devices[idx]);
				rc = wc->cbs.on_device_start(wc, wcd, idx, wc->cbs.user);
				if (rc != WC_EXE_OK) {
					WC_ERROR("Device %u returned error: %d\n", idx, rc);
					break;
				}
			}
			if (rc != WC_EXE_OK)
				break;
		}
		// TODO: we need to do the main stuff here
		// let's invoke the device finish functions
		if (wc->cbs.on_device_finish) {
			for (idx = 0; idx < wc->ocl.device_max; ++idx) {
				wc_cldev_t *wcd = &(wc->ocl.devices[idx]);
				rc = wc->cbs.on_device_finish(wc, wcd, idx, wc->cbs.user);
				if (rc != WC_EXE_OK) {
					WC_ERROR("Device %u returned error: %d\n", idx, rc);
					break;
				}
			}
			if (rc != WC_EXE_OK)
				break;
		}
		// XXX: Steps for invocation
		// collect total number of tasks on the master, send to slaves later
		// collect per task data on the master, send to slaves later
		// collect global data on the master, send to slaves later
		// process kernels on each system
		// retrieve data for each kernel output
		// send to master for aggregation
	} while (0);
	// if rc had an earlier value keep that
	rc |= wc_executor_post_run(wc, &current_state);
	return rc;
}

static const char *wc_devtype_to_string(const wc_devtype_t devt)
{
#undef DEV2STR
#define DEV2STR(A) case A: return #A
	switch (devt) {
	DEV2STR(WC_DEVTYPE_CPU);
	DEV2STR(WC_DEVTYPE_GPU);
	DEV2STR(WC_DEVTYPE_ANY);
	default: return "unknown";
	}
#undef DEV2STR
}

void wc_executor_dump(const wc_exec_t *wc)
{
	if (wc) {
		if (wc->mpi_initialized) {
			WC_INFO("MPI has been initialized successfully.\n");
		}
		WC_INFO("Total Peer Count: %d\n", wc->peer_count);
		WC_INFO("My Peer Id: %d\n", wc->peer_id);
		if (wc->ocl_initialized) {
			WC_INFO("OpenCL has been initialized successfully.\n");
			wc_opencl_dump(&(wc->ocl));
		}
		if (wc->callbacks_set) {
			WC_INFO("Callbacks have been set.\n");
			WC_INFO("Max Devices: %u\n", wc->cbs.max_devices);
			WC_INFO("Device Type: %s\n",
					wc_devtype_to_string(wc->cbs.device_type));
		}
	}
}

uint64_t wc_executor_num_tasks(const wc_exec_t *wc)
{
	return (wc) ? wc->num_tasks : 0;
}

uint32_t wc_executor_num_devices(const wc_exec_t *wc)
{
	if (wc && wc->ocl_initialized) {
		return wc->ocl.device_max;
	}
	return 0;
}
