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

enum {
	WC_EXECSTATE_NOT_STARTED = 0,
	WC_EXECSTATE_OPENCL_INITED,
	WC_EXECSTATE_STARTED,
	WC_EXECSTATE_GOT_CODE,
	WC_EXECSTATE_GOT_BUILDOPTS,
	WC_EXECSTATE_COMPILED_CODE,
	WC_EXECSTATE_GOT_TASKS4SYSTEM,
	WC_EXECSTATE_GOT_GLOBALDATA_LENGTH,
	WC_EXECSTATE_GOT_GLOBALDATA,
	WC_EXECSTATE_GOT_NUMTASKS,
	WC_EXECSTATE_GOT_TASKRANGEMULTIPLIER,
	WC_EXECSTATE_DATA_DECOMPOSED,
	WC_EXECSTATE_GOT_TASKRANGES,
	WC_EXECSTATE_DEVICE_STARTED,
	WC_EXECSTATE_DEVICE_DONE_RUNNING,
	WC_EXECSTATE_DEVICE_FINISHED,
	WC_EXECSTATE_FREED_GLOBALDATA,
	WC_EXECSTATE_FINISHED
};

struct wc_executor_details {
	int num_systems;
	int system_id;
	uint8_t mpi_initialized;
	wc_exec_callbacks_t cbs;
	uint8_t callbacks_set;
	wc_opencl_t ocl;
	uint8_t ocl_initialized;
	char *code;
	size_t codelen;
	char *buildopts;
	uint64_t num_tasks;
	uint32_t task_range_multiplier;
	wc_data_t globaldata;
	int state;
	// we track each system's total possibilities
	uint64_t my_tasks4system; // self-tasks-per-system
	uint64_t *all_tasks4system; //array of num_systems for master
	uint64_t my_task_range[2]; // my range of tasks
	uint64_t *task_ranges; // range of tasks per system
	volatile int64_t refcount;
	cl_event userevent;
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
		wc->num_systems = wc_mpi_peer_count();
		if (wc->num_systems < 0) {
			rc = -1;
			break;
		}
		wc->system_id = wc_mpi_peer_id();
		if (wc->system_id < 0) {
			rc = -1;
			break;
		}
		wc->ocl_initialized = 0;
		wc->callbacks_set = 0;
		wc->cbs.user = NULL;
		wc->cbs.max_devices = 0;
		wc->cbs.device_type = WC_DEVTYPE_ANY;
		wc->state = WC_EXECSTATE_NOT_STARTED;
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
		WC_FREE(wc->task_ranges);
		WC_FREE(wc->all_tasks4system);
		WC_FREE(wc->globaldata.ptr);
		wc->globaldata.len = 0;
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

int wc_executor_num_systems(const wc_exec_t *wc)
{
	return (wc) ? wc->num_systems : WC_EXE_ERR_INVALID_PARAMETER;
}

int wc_executor_system_id(const wc_exec_t *wc)
{
	return (wc) ? wc->system_id : WC_EXE_ERR_INVALID_PARAMETER;
}

wc_err_t wc_executor_setup(wc_exec_t *wc, const wc_exec_callbacks_t *cbs)
{
	if (wc && cbs) {
		// verify if the required callbacks are present
		if (!cbs->get_code || !cbs->get_num_tasks ||
			!cbs->on_device_range_exec) {
			WC_ERROR("Wisecracker needs the get_code, get_num_tasks and"
					" on_device_range_exec callbacks.\n");
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

static wc_err_t wc_executor_pre_run(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		wc->state = WC_EXECSTATE_NOT_STARTED;
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
		wc->state = WC_EXECSTATE_OPENCL_INITED;
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
		wc->state = WC_EXECSTATE_STARTED;
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
		wc->state = WC_EXECSTATE_GOT_CODE;
		// call the build_opts function to retrieve the build options
		if (wc->cbs.get_build_options) {
			WC_FREE(wc->buildopts); // clear the previous loaded options
			wc->buildopts = wc->cbs.get_build_options(wc, wc->cbs.user);
			if (!wc->buildopts) {
				WC_WARN("Build options returned was NULL.\n");
			}
		}
		wc->state = WC_EXECSTATE_GOT_BUILDOPTS;
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
		wc->state = WC_EXECSTATE_COMPILED_CODE;
	} while (0);
	return rc;
}

static wc_err_t wc_executor_post_run(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (wc->cbs.free_global_data) {
		wc->cbs.free_global_data(wc, wc->cbs.user, &wc->globaldata);
	} else {
		// free the global data
		WC_FREE(wc->globaldata.ptr);
	}
	wc->globaldata.ptr = NULL;
	wc->globaldata.len = 0;
	wc->state = WC_EXECSTATE_FREED_GLOBALDATA;
	// call the on_finish event
	if (wc->state != WC_EXECSTATE_NOT_STARTED && wc->cbs.on_finish) {
		rc = wc->cbs.on_finish(wc, wc->cbs.user);
		if (rc != WC_EXE_OK) {
			WC_ERROR("Error in on_finish callback: %d\n", rc);
		}
		wc->state = WC_EXECSTATE_FINISHED;
	}
	return rc;
}

static uint64_t wc_executor_tasks4system(const wc_opencl_t *ocl)
{
	uint64_t total_tasks = 0;
	if (ocl) {
		uint32_t idx;
		for (idx = 0; idx < ocl->device_max; ++idx) {
			const wc_cldev_t *dev = &ocl->devices[idx];
			total_tasks += (dev->workgroup_sz * dev->compute_units);
		}
	}
	return total_tasks;
}

static wc_err_t wc_executor_master_pre_run(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		int idx;
		uint64_t sum_tasks, num_rounds, start, end;
		// free the old stuff
		WC_FREE(wc->all_tasks4system);
		wc->all_tasks4system = WC_MALLOC(wc->num_systems * sizeof(uint64_t));
		if (!wc->all_tasks4system) {
			WC_ERROR_OUTOFMEMORY(wc->num_systems * sizeof(uint64_t));
			rc = WC_EXE_ERR_OUTOFMEMORY;
			break;
		}
		memset(wc->all_tasks4system, 0, sizeof(uint64_t) * wc->num_systems);
		wc->my_tasks4system = wc_executor_tasks4system(&wc->ocl);
		wc->all_tasks4system[wc->system_id] = wc->my_tasks4system;
		// receive the data from all systems using MPI_Gather
		if (wc->mpi_initialized) {
			int err = wc_mpi_gather(&wc->my_tasks4system, 1,
					MPI_UNSIGNED_LONG_LONG, wc->all_tasks4system, 1,
					MPI_UNSIGNED_LONG_LONG, wc->system_id);
			if (err < 0) {
				WC_ERROR("Unable to share the tasks per system info."
						" MPI Error: %d\n", err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
		} else {
			WC_WARN("MPI Not initialized. Not exchanging task info.\n");
		}
		wc->state = WC_EXECSTATE_GOT_TASKS4SYSTEM;
		// dump the info you get from slaves
		for (idx = 0; idx < wc->num_systems; ++idx) {
			WC_DEBUG("System[%u] has tasks: %"PRIu64"\n", idx,
					wc->all_tasks4system[idx]);
		}
		wc->globaldata.ptr = NULL;
		wc->globaldata.len = 0;
		// get and send the global data across
		if (wc->cbs.get_global_data) {
			wc_data_t gdata = { 0 };
			rc = wc->cbs.get_global_data(wc, wc->cbs.user, &gdata);
			if (rc != WC_EXE_OK) {
				WC_ERROR("Error retrieving global data: %d\n", rc);
				break;
			}
			wc->globaldata.ptr = gdata.ptr;
			wc->globaldata.len = gdata.len;
			if (wc->globaldata.ptr && wc->globaldata.len == 0) {
				WC_ERROR("Global data pointer is not NULL but length is 0\n");
				rc = WC_EXE_ERR_BAD_STATE;
				break;
			}
		}
		// inform the slaves to receive global data of given length. can be 0
		// which means it will not receive any data
		if (wc->mpi_initialized) {
			int err = wc_mpi_broadcast(&wc->globaldata.len, 1, MPI_UNSIGNED,
										wc->system_id);
			if (err < 0) {
				WC_ERROR("Unable to share the global data length information."
						" MPI Error: %d\n", err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
		} else {
			WC_WARN("MPI Not initialized. Not sending global data length\n");
		}
		wc->state = WC_EXECSTATE_GOT_GLOBALDATA_LENGTH;
		WC_DEBUG("Sent global data length: %u\n", wc->globaldata.len);
		// send the global data across to all the systems
		if (wc->globaldata.len > 0 && wc->mpi_initialized) {
			int err = wc_mpi_broadcast(wc->globaldata.ptr,
					(int)wc->globaldata.len, MPI_BYTE, wc->system_id);
			if (err < 0) {
				WC_ERROR("Unable to share the global data. MPI Error: %d\n",
						err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
		} else {
			if (!wc->globaldata.ptr || wc->globaldata.len == 0) {
				WC_INFO("No global data to send.\n");
			}
			if (!wc->mpi_initialized && wc->globaldata.ptr) {
				WC_WARN("MPI Not initialized. Not sending global data.\n");
			}
		}
		wc->state = WC_EXECSTATE_GOT_GLOBALDATA;
		WC_DEBUG("Sent global data across\n");
		// get task decomposition
		// FIXME: we can add another callback to retrieve a more detailed
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
			WC_DEBUG("No of Tasks: %"PRIu64"\n", wc->num_tasks);
		}
		wc->state = WC_EXECSTATE_GOT_NUMTASKS;
		if (wc->cbs.get_task_range_multiplier) {
			wc->task_range_multiplier = wc->cbs.get_task_range_multiplier(wc,
										wc->cbs.user);
		}
		if (wc->task_range_multiplier < 1)
			wc->task_range_multiplier = 1;
		wc->state = WC_EXECSTATE_GOT_TASKRANGEMULTIPLIER;
		WC_DEBUG("Task Range multiplier: %u\n", wc->task_range_multiplier);
		if (!wc->ocl_initialized) {
			WC_ERROR("OpenCL is not initialized.\n");
			rc = WC_EXE_ERR_BAD_STATE;
			break;
		}
		// Do data decomposition here
		WC_FREE(wc->task_ranges);
		wc->task_ranges = WC_MALLOC(wc->num_systems * sizeof(uint64_t) * 2);
		if (!wc->task_ranges) {
			WC_ERROR_OUTOFMEMORY(wc->num_systems * sizeof(uint64_t) * 2);
			rc = WC_EXE_ERR_OUTOFMEMORY;
			break;
		}
		memset(wc->task_ranges, 0, wc->num_systems * sizeof(uint64_t) * 2);
		sum_tasks = 0;
		for (idx = 0; idx < wc->num_systems; ++idx)
			sum_tasks += wc->all_tasks4system[idx];
		sum_tasks *= wc->task_range_multiplier;
		if (sum_tasks >= wc->num_tasks)
			num_rounds = 1;
		else
			num_rounds = (wc->num_tasks / sum_tasks) +
						((wc->num_tasks % sum_tasks) ? 1 : 0);
		if (num_rounds <= 1)
			num_rounds = 1;
		WC_DEBUG("no. of rounds %"PRIu64"\n", num_rounds);
		// create system task ranges
		start = end = 0;
		for (idx = 0; idx < wc->num_systems; ++idx) {
			end += wc->all_tasks4system[idx] * wc->task_range_multiplier *
					num_rounds;
			wc->task_ranges[2 * idx] = start;
			wc->task_ranges[2 * idx + 1] = end;
			if (end >= wc->num_tasks) {
				wc->task_ranges[2 * idx + 1] = wc->num_tasks - start;
				break;
			}
			start = end;
		}
		wc->state = WC_EXECSTATE_DATA_DECOMPOSED;
		wc->my_task_range[0] = wc->task_ranges[2 * wc->system_id];
		wc->my_task_range[1] = wc->task_ranges[2 * wc->system_id + 1];
		// ok now scatter the data across the slaves
		if (wc->mpi_initialized) {
			int err;
			err = wc_mpi_broadcast(&wc->num_tasks, 1, MPI_UNSIGNED_LONG_LONG,
								wc->system_id);
			if (err < 0) {
				WC_ERROR("Unable to send num tasks to slaves. MPI Error: %d\n",
						err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
			WC_DEBUG("Sent num tasks as %"PRIu64"\n", wc->num_tasks);
			err = wc_mpi_scatter(wc->task_ranges, 2,
						MPI_UNSIGNED_LONG_LONG, wc->my_task_range, 2,
						MPI_UNSIGNED_LONG_LONG, wc->system_id);
			if (err < 0) {
				WC_ERROR("Unable to share the tasks ranges with others."
						" MPI Error: %d\n", err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
		} else {
			WC_WARN("MPI Not initialized. Not sending task ranges \n");
		}
		wc->state = WC_EXECSTATE_GOT_TASKRANGES;
		WC_DEBUG("Task Range: (%"PRIu64", %"PRIu64")\n",
					wc->my_task_range[0], wc->my_task_range[1]);
	} while (0);
	return rc;
}

static wc_err_t wc_executor_slave_pre_run(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		uint32_t recvglob = 0;
		// free the old stuff. allocate just to be safe from bad MPI
		// implementations
		WC_FREE(wc->all_tasks4system);
		wc->all_tasks4system = WC_MALLOC(wc->num_systems * sizeof(uint64_t));
		if (!wc->all_tasks4system) {
			WC_ERROR_OUTOFMEMORY(wc->num_systems * sizeof(uint64_t));
			rc = WC_EXE_ERR_OUTOFMEMORY;
			break;
		}
		memset(wc->all_tasks4system, 0, sizeof(uint64_t) * wc->num_systems);
		// send device information from other systems
		wc->my_tasks4system = wc_executor_tasks4system(&wc->ocl);
		wc->all_tasks4system[wc->system_id] = wc->my_tasks4system;
		// receive the data from all systems using MPI_Gather
		if (wc->mpi_initialized) {
			int err = wc_mpi_gather(&wc->my_tasks4system, 1,
					MPI_UNSIGNED_LONG_LONG, wc->all_tasks4system, 1,
					MPI_UNSIGNED_LONG_LONG, 0); // root id is 0
			if (err < 0) {
				WC_ERROR("Unable to share the tasks per system info."
						" MPI Error: %d\n", err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
		} else {
			WC_WARN("MPI Not initialized. Not exchanging task info.\n");
		}
		wc->state = WC_EXECSTATE_GOT_TASKS4SYSTEM;
		// receive the global data here
		// get the global data length
		recvglob = 0;
		if (wc->mpi_initialized) {
			int err = wc_mpi_broadcast(&recvglob, 1, MPI_UNSIGNED, 0);
			if (err < 0) {
				WC_ERROR("Unable to share the global data length information."
						" MPI Error: %d\n", err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
		} else {
			WC_WARN("MPI Not initialized. Not receiving global data length\n");
		}
		wc->state = WC_EXECSTATE_GOT_GLOBALDATA_LENGTH;
		wc->globaldata.ptr = NULL;
		wc->globaldata.len = recvglob;
		WC_DEBUG("Received global data length: %u\n", wc->globaldata.len);
		// get the global data buffer if needed
		if (wc->globaldata.len > 0 && wc->mpi_initialized) {
			int err;
			wc->globaldata.ptr = WC_MALLOC(wc->globaldata.len);
			if (!wc->globaldata.ptr) {
				WC_ERROR_OUTOFMEMORY(wc->globaldata.len);
				rc = WC_EXE_ERR_OUTOFMEMORY;
				break;
			}
			err = wc_mpi_broadcast(wc->globaldata.ptr, (int)wc->globaldata.len,
									MPI_BYTE, 0);
			if (err < 0) {
				WC_ERROR("Unable to share the global data. MPI Error: %d\n",
						err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
		} else {
			if (!wc->globaldata.ptr || wc->globaldata.len == 0) {
				WC_INFO("No global data to receive.\n");
			}
			if (!wc->mpi_initialized) {
				WC_WARN("MPI Not initialized. Not receiving global data.\n");
			}
		}
		WC_DEBUG("Received global data from master\n");
		// now call the on_recv_globaldata callback on slaves only
		if (wc->cbs.on_receive_global_data) {
			rc = wc->cbs.on_receive_global_data(wc, wc->cbs.user,
												&wc->globaldata);
			if (rc != WC_EXE_OK) {
				WC_ERROR("Error in on_receive_global_data callback: %d\n", rc);
				break;
			}
		}
		wc->state = WC_EXECSTATE_GOT_GLOBALDATA;
		// we might not need this allocation but just want to be safe from MPI
		// implementation differences
		WC_FREE(wc->task_ranges);
		wc->task_ranges = WC_MALLOC(wc->num_systems * sizeof(uint64_t) * 2);
		if (!wc->task_ranges) {
			WC_ERROR_OUTOFMEMORY(wc->num_systems * sizeof(uint64_t) * 2);
			rc = WC_EXE_ERR_OUTOFMEMORY;
			break;
		}
		memset(wc->task_ranges, 0, wc->num_systems * sizeof(uint64_t) * 2);
		wc->my_task_range[0] = 0;
		wc->my_task_range[1] = 0;
		// wait for getting task division from the master
		if (wc->mpi_initialized) {
			int err;
			err = wc_mpi_broadcast(&wc->num_tasks, 1, MPI_UNSIGNED_LONG_LONG,
									0);
			if (err < 0) {
				WC_ERROR("Unable to get num tasks from master. MPI Error: %d\n",
						err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
			WC_DEBUG("Received num tasks as %"PRIu64"\n", wc->num_tasks);
			err = wc_mpi_scatter(wc->task_ranges, 2,
						MPI_UNSIGNED_LONG_LONG, wc->my_task_range, 2,
						MPI_UNSIGNED_LONG_LONG, 0);
			if (err < 0) {
				WC_ERROR("Unable to get the task range from the master."
						" MPI Error: %d\n", err);
				rc = WC_EXE_ERR_MPI;
				break;
			}
			wc->task_ranges[2 * wc->system_id] = wc->my_task_range[0];
			wc->task_ranges[2 * wc->system_id + 1] = wc->my_task_range[1];
			WC_DEBUG("Task Range: (%"PRIu64", %"PRIu64")\n",
					wc->my_task_range[0], wc->my_task_range[1]);
		} else {
			WC_WARN("MPI Not initialized. Not receiving task ranges \n");
		}
		wc->state = WC_EXECSTATE_GOT_TASKRANGES;
	} while (0);
	return rc;
}

static void CL_CALLBACK wc_executor_device_event_notify(cl_event ev,
										cl_int status, void *user)
{
	wc_exec_t *wc = (wc_exec_t *)user;
	if (!wc || !wc->userevent)
		return;
	// reduce the reference count until it hits 1
	wc->refcount--;
	// WC_DEBUG("wrefcount=%ld \n", wc->refcount);
	// the reference count has hit 0
	if (wc->refcount == 0) {
		// WC_DEBUG("setting the user event\n");
		wc_opencl_event_set(wc->userevent);
	}
}

static wc_err_t wc_executor_device_start(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		if (!wc->ocl_initialized || !wc_opencl_is_usable(&wc->ocl)) {
			WC_ERROR("OpenCL internal runtime is not usable\n");
			rc = WC_EXE_ERR_BAD_STATE;
			break;
		}
		// ok let's invoke the device start functions
		if (wc->cbs.on_device_start) {
			uint32_t idx;
			for (idx = 0; idx < wc->ocl.device_max; ++idx) {
				wc_cldev_t *dev = &(wc->ocl.devices[idx]);
				rc = wc->cbs.on_device_start(wc, dev, idx, wc->cbs.user,
											&wc->globaldata);
				if (rc != WC_EXE_OK) {
					WC_ERROR("Device %u returned error: %d\n", idx, rc);
					break;
				}
			}
			if (rc != WC_EXE_OK)
				break;
		}
		wc->state = WC_EXECSTATE_DEVICE_STARTED;
	} while (0);
	return rc;
}

static wc_err_t wc_executor_device_finish(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		if (!wc->ocl_initialized || !wc_opencl_is_usable(&wc->ocl)) {
			WC_ERROR("OpenCL internal runtime is not usable\n");
			rc = WC_EXE_ERR_BAD_STATE;
			break;
		}
		// let's invoke the device finish functions
		if (wc->cbs.on_device_finish) {
			uint32_t idx;
			for (idx = 0; idx < wc->ocl.device_max; ++idx) {
				wc_cldev_t *dev = &(wc->ocl.devices[idx]);
				rc = wc->cbs.on_device_finish(wc, dev, idx, wc->cbs.user,
											&wc->globaldata);
				if (rc != WC_EXE_OK) {
					WC_ERROR("Device %u returned error: %d\n", idx, rc);
					break;
				}
			}
			if (rc != WC_EXE_OK)
				break;
		}
		wc->state = WC_EXECSTATE_DEVICE_FINISHED;
	} while (0);
	return rc;
}

static wc_err_t wc_executor_single_system_run(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	cl_event *events = NULL;
	cl_ulong2 *device_ranges = NULL;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		rc = wc_executor_device_start(wc);
		if (rc != WC_EXE_OK)
			break;
		events = WC_MALLOC(sizeof(cl_event) * wc->ocl.device_max);
		if (!events) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_event) * wc->ocl.device_max);
			rc = WC_EXE_ERR_OUTOFMEMORY;
			break;
		}
		memset(events, 0, sizeof(cl_event) * wc->ocl.device_max);
		device_ranges = WC_MALLOC(sizeof(cl_ulong2) * wc->ocl.device_max);
		if (!device_ranges) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_ulong2) * wc->ocl.device_max);
			rc = WC_EXE_ERR_OUTOFMEMORY;
			break;
		}
		memset(device_ranges, 0, sizeof(cl_ulong2) * wc->ocl.device_max);
		// we need to do the main stuff here for the current system
		do {
			uint64_t tasks_completed = 0;
			uint32_t idx;
			uint64_t num_tasks = 0;

			tasks_completed = 0;
			num_tasks = wc->my_task_range[1] - wc->my_task_range[0];
			if (num_tasks == 0)
				break;
			do {
				uint64_t start, end;
				rc = WC_EXE_OK;
				wc->refcount = 0;
				wc->userevent = (cl_event)0;
				wc->userevent = wc_opencl_event_create(&wc->ocl);
				if (!wc->userevent) {
					rc = WC_EXE_ERR_OPENCL;
					WC_WARN("User event failed to create. Shaky state\n");
					break;
				}
				start = wc->my_task_range[0];
				end = 0;
				for (idx = 0; idx < wc->ocl.device_max; ++idx) {
					uint64_t tasks4device;
					wc_cldev_t *dev = &(wc->ocl.devices[idx]);
					events[idx] = (cl_event)0;
					tasks4device = dev->workgroup_sz * dev->compute_units *
									wc->task_range_multiplier;
					end = start + tasks4device;
					if (end >= wc->my_task_range[1])
						end = wc->my_task_range[1];
					device_ranges[idx].s[0] = start;
					device_ranges[idx].s[1] = end;
					rc = wc->cbs.on_device_range_exec(wc, dev, idx,
							wc->cbs.user, &wc->globaldata, start, end,
							&events[idx]);
					if (rc != WC_EXE_OK) {
						WC_ERROR("Error occurred while running device work:"
								" Range(%"PRIu64",%"PRIu64"). Completed(%"PRIu64")\n",
								start, end, tasks_completed);
						break;
					}
					// Wait for events here
					// if no events are returned then we don't care and will not
					// wait for anything
					if (events[idx]) {
						if (wc_opencl_event_enqueue_wait(dev, &events[idx], 1,
									wc_executor_device_event_notify, wc) < 0) {
							rc = WC_EXE_ERR_OPENCL;
							WC_ERROR("Unable to set wait for event\n");
							break;
						}
						wc->refcount++;
					}
					// flush the command queue for the device
					if (wc_opencl_flush_cmdq(dev) < 0) {
						rc = WC_EXE_ERR_OPENCL;
						break;
					}
					tasks_completed += end - start;
					start = end;
					if (start >= wc->my_task_range[1])
						break;
					if (tasks_completed >= num_tasks)
						break;
				}
				if (rc != WC_EXE_OK || rc < 0)
					break;
				// we have events to wait for
				if (wc->refcount > 0) {
					rc = wc_opencl_event_wait(&wc->userevent, 1);
					if (rc < 0) {
						rc = WC_EXE_ERR_OPENCL;
						break;
					}
				}
				// gets here when event is set
				wc_opencl_event_release(wc->userevent);
				wc->userevent = (cl_event)0;
				for (idx = 0; idx < wc->ocl.device_max; ++idx) {
					if (events[idx])
						wc_opencl_event_release(events[idx]);
					events[idx] = (cl_event)0;
				}
				//FIXME; should we call this on demand @ every event callback or
				//wait for the collection of events to complete first ?
				if (wc->cbs.on_device_range_done) {
					for (idx = 0; idx < wc->ocl.device_max; ++idx) {
						wc_cldev_t *dev = &(wc->ocl.devices[idx]);
						wc_data_t results = { 0 };
						wc_err_t slverr = wc->cbs.on_device_range_done(wc, dev,
								idx, wc->cbs.user, &wc->globaldata,
								device_ranges[idx].s[0],
								device_ranges[idx].s[1],
								&results);
						//send data back to master and invoke the
						//on-receive event
						if (wc->cbs.on_receive_range_results) {
							wc_err_t msterr = wc->cbs.on_receive_range_results(wc,
									wc->cbs.user, device_ranges[idx].s[0],
									device_ranges[idx].s[1], &results);
							//propagate this stop to slaves
							if (msterr == WC_EXE_STOP) {
								WC_INFO("User requested a stop.\n");
								rc = msterr;
								break;
							}
							if (msterr != WC_EXE_OK) {
								WC_ERROR("Error occurred in callback\n");
								rc = WC_EXE_ERR_BAD_STATE;
								break;
							}
						}
						//propagate this stop to master
						if (slverr == WC_EXE_STOP) {
							WC_INFO("User requested a stop.\n");
							rc = slverr;
							break;
						}
						if (slverr != WC_EXE_OK) {
							WC_ERROR("Error occurred in callback\n");
							rc = WC_EXE_ERR_BAD_STATE;
							break;
						}
						// do this on both master and slave
						WC_FREE(results.ptr);
					}
				}
				// call progress only on master based on tasks completed
				if (wc->cbs.progress) {
					double percent = ((double)(100.0 * tasks_completed)) /
															num_tasks;
					wc->cbs.progress((float)percent, wc->cbs.user);
				}
				if (rc != WC_EXE_OK)
					break;
			} while (tasks_completed < num_tasks);
			if (rc != WC_EXE_OK)
				break;
		} while (0);
		wc->state = WC_EXECSTATE_DEVICE_DONE_RUNNING;
		if (rc != WC_EXE_OK && rc != WC_EXE_STOP)
			break;
		rc = wc_executor_device_finish(wc);
		if (rc != WC_EXE_OK)
			break;
	} while (0);
	WC_FREE(events);
	WC_FREE(device_ranges);
	return rc;
}

static int wc_loop_breaker = 0;
struct wc_exec_result {
	uint64_t start;
	uint64_t end;
	wc_data_t result;
	wc_err_t err;
};
#define WC_TAG_MST_STOP 0x0000FACE
#define WC_TAG_SLV_ERRORS 0x0000DEAD
#define WC_TAG_SLV_RANGES 0x0000CAFE
#define WC_TAG_SLV_RESULTS 0x0000BEEF
#define WC_MAX_SLV_REQUESTS 3

// we want to split the master_run into 2 functions
WC_THREAD_RETURN wc_executor_master_receiver(void *arg)
{
	wc_exec_t *wc = (wc_exec_t *)arg;
	if (!wc) {
		WC_ERROR("Thread argument was NULL\n");
		return (WC_THREAD_RETURN)0;
	}
	wc_loop_breaker = 0;
	while (!wc_loop_breaker) {
					/*
						//TODO: send data back to master and invoke the
						//on-receive event
						if (wc->cbs.on_receive_range_results) {
							wc_err_t msterr = wc->cbs.on_receive_range_results(wc,
									wc->cbs.user, device_ranges[idx].s[0],
									device_ranges[idx].s[1], &results);
							//TODO: propagate this stop to slaves
							if (msterr == WC_EXE_STOP) {
								WC_INFO("User requested a stop.\n");
								rc = msterr;
								break;
							}
							if (msterr != WC_EXE_OK) {
								WC_ERROR("Error occurred in callback\n");
								rc = WC_EXE_ERR_BAD_STATE;
								break;
							}
						}
						//TODO: propagate this stop to master
						if (slverr == WC_EXE_STOP) {
							WC_INFO("User requested a stop.\n");
							rc = slverr;
							break;
						}
						if (slverr != WC_EXE_OK) {
							WC_ERROR("Error occurred in callback\n");
							rc = WC_EXE_ERR_BAD_STATE;
							break;
						}
						// do this on both master and slave
						WC_FREE(results.ptr);
				// TODO: call progress only on master based on tasks completed
				if (wc->cbs.progress) {
					double percent = ((double)(100.0 * tasks_completed)) /
															num_tasks;
					wc->cbs.progress((float)percent, wc->cbs.user);
				}
					*/
	}
	return (WC_THREAD_RETURN)0;
}

static wc_err_t wc_executor_serialize(const wc_data_t *data, size_t count,
									  wc_data_t *out)
{
	size_t sendcount = 0;
	unsigned char *sendbuf = NULL;
	wc_err_t rc = WC_EXE_OK;
	do {
		unsigned char *ptr;
		size_t idx;
		if (!data || count == 0 || !out) {
			rc = WC_EXE_ERR_INVALID_PARAMETER;
			break;
		}
		sendcount = 0;
		for (idx = 0; idx < count; ++idx) {
			sendcount += data[idx].len;
			sendcount += sizeof(data[idx].len);
		}
		sendbuf = WC_MALLOC(sendcount);
		if (!sendbuf) {
			WC_ERROR_OUTOFMEMORY(sendcount);
			rc = WC_EXE_ERR_OUTOFMEMORY;
			break;
		}
		memset(sendbuf, 0, sendcount);
		ptr = sendbuf;
		for (idx = 0; idx < count; ++idx) {
			memcpy(ptr, &data[idx].len, sizeof(data[idx].len));
			ptr += sizeof(data[idx].len);
			if (data[idx].ptr && data[idx].len > 0) {
				memcpy(ptr, data[idx].ptr, data[idx].len);
				ptr += data[idx].len;
			}
		}
	} while (0);
	if (out) {
		out->ptr = sendbuf;
		out->len = sendcount;
	}
	return rc;
}

static wc_err_t wc_executor_slave_check_stop()
{
	int flag = 0;
	// check for message from master here and break if needed
	if (wc_mpi_iprobe(0, WC_TAG_MST_STOP, &flag) < 0) {
		WC_ERROR("Unable to probe for master's messages\n");
		return WC_EXE_ERR_MPI;
	}
	// receive the message from master
	if (flag == 1) {
		wc_err_t msterr = WC_EXE_OK;
		if (wc_mpi_recv(&msterr, 1, MPI_INT, 0, WC_TAG_MST_STOP) < 0) {
			WC_ERROR("Unable to receive a stop from the master\n");
			return WC_EXE_ERR_MPI;
		}
		if (msterr != WC_EXE_STOP) {
			WC_WARN("Received %d from master instead of stop\n",
					msterr);
		} else {
			WC_INFO("Received stop from master\n");
		}
		return WC_EXE_STOP;
	}
	return WC_EXE_OK;
}

static wc_err_t wc_executor_slave_system_run(wc_exec_t *wc)
{
#undef LOCAL_MALLOC_DEVICE_ARRAY
#define LOCAL_MALLOC_DEVICE_ARRAY(PTR,TYPE,MUL) \
do { \
	(PTR) = WC_MALLOC(sizeof(TYPE) * wc->ocl.device_max * (MUL)); \
	if ((PTR) == NULL) { \
		WC_ERROR_OUTOFMEMORY(sizeof(TYPE) * wc->ocl.device_max * (MUL)); \
		rc = WC_EXE_ERR_OUTOFMEMORY; \
		break; \
	} \
	memset((PTR), 0, sizeof(TYPE) * wc->ocl.device_max * (MUL)); \
	rc = WC_EXE_OK; \
} while (0)
	wc_err_t rc = WC_EXE_OK;
	cl_event *device_events = NULL;
	uint64_t *device_ranges = NULL;
	wc_err_t *device_errs = NULL;
	wc_data_t *device_results = NULL;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		LOCAL_MALLOC_DEVICE_ARRAY(device_events, cl_event, 1);
		if (rc != WC_EXE_OK)
			break;
		LOCAL_MALLOC_DEVICE_ARRAY(device_ranges, uint64_t, 2);
		if (rc != WC_EXE_OK)
			break;
		LOCAL_MALLOC_DEVICE_ARRAY(device_errs, wc_err_t, 1);
		if (rc != WC_EXE_OK)
			break;
		LOCAL_MALLOC_DEVICE_ARRAY(device_results, wc_data_t, 1);
		if (rc != WC_EXE_OK)
			break;
		rc = wc_executor_device_start(wc);
		if (rc != WC_EXE_OK)
			break;
		// we need to do the main stuff here for the current system
		do {
			uint64_t tasks_completed = 0;
			uint32_t idx;
			uint64_t num_tasks = 0;

			tasks_completed = 0;
			num_tasks = wc->my_task_range[1] - wc->my_task_range[0];
			if (num_tasks == 0)
				break;
			do {
				uint64_t start, end;
				rc = WC_EXE_OK;
				wc->refcount = 0;
				wc->userevent = (cl_event)0;
				wc->userevent = wc_opencl_event_create(&wc->ocl);
				if (!wc->userevent) {
					rc = WC_EXE_ERR_OPENCL;
					WC_WARN("User event failed to create. Shaky state\n");
					break;
				}
				start = wc->my_task_range[0];
				end = 0;
				for (idx = 0; idx < wc->ocl.device_max; ++idx) {
					uint64_t tasks4device;
					wc_cldev_t *dev = &(wc->ocl.devices[idx]);
					device_events[idx] = (cl_event)0;
					tasks4device = dev->workgroup_sz * dev->compute_units *
									wc->task_range_multiplier;
					end = start + tasks4device;
					if (end >= wc->my_task_range[1])
						end = wc->my_task_range[1];
					device_ranges[2 * idx] = start;
					device_ranges[2 * idx + 1] = end;
					rc = wc->cbs.on_device_range_exec(wc, dev, idx,
							wc->cbs.user, &wc->globaldata, start, end,
							&device_events[idx]);
					if (rc != WC_EXE_OK) {
						WC_ERROR("Error occurred while running device work:"
								" Range(%"PRIu64",%"PRIu64"). Completed(%"PRIu64")\n",
								start, end, tasks_completed);
						break;
					}
					// Wait for events here
					// if no events are returned then we don't care and will not
					// wait for anything
					if (device_events[idx]) {
						if (wc_opencl_event_enqueue_wait(dev,
								&device_events[idx], 1,
								wc_executor_device_event_notify, wc) < 0) {
							rc = WC_EXE_ERR_OPENCL;
							WC_ERROR("Unable to set wait for event\n");
							break;
						}
						wc->refcount++;
					}
					// flush the command queue for the device
					if (wc_opencl_flush_cmdq(dev) < 0) {
						rc = WC_EXE_ERR_OPENCL;
						break;
					}
					tasks_completed += end - start;
					start = end;
					if (start >= wc->my_task_range[1])
						break;
					if (tasks_completed >= num_tasks)
						break;
				}
				if (rc != WC_EXE_OK || rc < 0)
					break;
				// we have events to wait for
				if (wc->refcount > 0) {
					rc = wc_opencl_event_wait(&wc->userevent, 1);
					if (rc < 0) {
						rc = WC_EXE_ERR_OPENCL;
						break;
					}
				}
				// gets here when event is set
				wc_opencl_event_release(wc->userevent);
				wc->userevent = (cl_event)0;
				for (idx = 0; idx < wc->ocl.device_max; ++idx) {
					if (device_events[idx])
						wc_opencl_event_release(device_events[idx]);
					device_events[idx] = (cl_event)0;
				}
				// we wait for the collection of events to finish first before
				// invoking this for every range
				if (wc->cbs.on_device_range_done) {
					wc_data_t senddata = { 0 };
					// minimum is 3. we just use this here
					wc_mpirequest_t requests[WC_MAX_SLV_REQUESTS];
					memset(requests, 0, sizeof(requests));
					for (idx = 0; idx < wc->ocl.device_max; ++idx) {
						wc_cldev_t *dev = &(wc->ocl.devices[idx]);
						device_results[idx].ptr = NULL;
						device_results[idx].len = 0;
						device_errs[idx] = wc->cbs.on_device_range_done(wc, dev,
							idx, wc->cbs.user, &wc->globaldata,
							device_ranges[2 * idx], device_ranges[2 * idx + 1],
							&device_results[idx]);
					}
					// send the errors from this range
					if (wc_mpi_isend(device_errs, wc->ocl.device_max, MPI_INT,
							0, WC_TAG_SLV_ERRORS, &requests[0]) < 0) {
						WC_ERROR("Error in sending device error codes\n");
						rc = WC_EXE_ERR_MPI;
						break;
					}
					// send the device range itself
					if (wc_mpi_isend(device_ranges, wc->ocl.device_max * 2,
							MPI_UNSIGNED_LONG_LONG, 0, WC_TAG_SLV_RANGES,
						   &requests[1]) < 0) {
						WC_ERROR("Error in sending device ranges\n");
						rc = WC_EXE_ERR_MPI;
						break;
					}
					// first serialize the data into 1 buffer
					// as opposed to using multiple buffers of varying lengths
					rc = wc_executor_serialize(device_results,
							wc->ocl.device_max, &senddata);
					if (rc != WC_EXE_OK)
						break;
					// free the individual results buffers first
					for (idx = 0; idx < wc->ocl.device_max; ++idx) {
						WC_FREE(device_results[idx].ptr);
					}
					// send the results for this range
					if (wc_mpi_isend(senddata.ptr, senddata.len, MPI_BYTE, 0,
								WC_TAG_SLV_RESULTS, &requests[2]) < 0) {
						WC_ERROR("Error in sending device results\n");
						rc = WC_EXE_ERR_MPI;
						break;
					}
					// wait for all the events to complete before moving on
					if (wc_mpi_wait(WC_MAX_SLV_REQUESTS, requests) < 0) {
						WC_ERROR("Error in waiting for all send events\n");
						rc = WC_EXE_ERR_MPI;
					}
					// free the results send buffer and then break;
					WC_FREE(senddata.ptr);
					if (rc != WC_EXE_OK)
						break;
				}
				// check for message from master before looping
				rc = wc_executor_slave_check_stop();
				if (rc != WC_EXE_OK)
					break;
			} while (tasks_completed < num_tasks);
			if (rc != WC_EXE_OK)
				break;
		} while (0);
		wc->state = WC_EXECSTATE_DEVICE_DONE_RUNNING;
		if (rc != WC_EXE_OK && rc != WC_EXE_STOP)
			break;
		rc = wc_executor_device_finish(wc);
		if (rc != WC_EXE_OK)
			break;
	} while (0);
	WC_FREE(device_events);
	WC_FREE(device_ranges);
	WC_FREE(device_errs);
	WC_FREE(device_results);
	return rc;
#undef LOCAL_MALLOC_DEVICE_ARRAY
}

static wc_err_t wc_executor_master_system_run(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	wc_thread_t thread = (wc_thread_t)0;
	if (WC_THREAD_CREATE(&thread, wc_executor_master_receiver, wc) != 0) {
		WC_ERROR("Failed to create master receiver thread.\n");
		return WC_EXE_ERR_SYSTEM;
	}
	rc = wc_executor_slave_system_run(wc);
	if (thread)
		WC_THREAD_JOIN(&thread);
	return rc;
}

wc_err_t wc_executor_run(wc_exec_t *wc)
{
	wc_err_t rc = WC_EXE_OK;
	if (!wc)
		return WC_EXE_ERR_INVALID_PARAMETER;
	do {
		wc->state = WC_EXECSTATE_NOT_STARTED;
		rc = wc_executor_pre_run(wc);
		if (rc != WC_EXE_OK)
			break;
		if (wc->system_id == 0) {
			rc = wc_executor_master_pre_run(wc);
		} else {
			rc = wc_executor_slave_pre_run(wc);
		}
		if (rc != WC_EXE_OK)
			break;
		// run the special method if single machine mode
		if (wc->system_id == 0 && wc->num_systems <= 1) {
			rc = wc_executor_single_system_run(wc);
		} else {
			if (wc->system_id == 0)
				rc = wc_executor_master_system_run(wc);
			else
				rc = wc_executor_slave_system_run(wc);
		}
		if (rc != WC_EXE_OK) {
			WC_WARN("error occurred during the run: %d\n", rc);
		}
		// continue to finish up the post run despite errors
		rc |= wc_executor_post_run(wc);
		if (rc != WC_EXE_OK)
			break;
	} while (0);
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
		WC_INFO("No. of Systems: %d\n", wc->num_systems);
		WC_INFO("My System Id: %d\n", wc->system_id);
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
