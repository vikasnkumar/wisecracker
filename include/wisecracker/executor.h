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
#ifndef __WISECRACKER_EXECUTOR_H__
#define __WISECRACKER_EXECUTOR_H__

EXTERN_C_BEGIN

#define WC_EXE_OK 0
#define WC_EXE_ERR_NONE WC_EXE_OK
#define WC_EXE_ABORT 1 /* not an error but an order */
#define WC_EXE_ERR_BAD_STATE -1
#define WC_EXE_ERR_OUTOFMEMORY -2
#define WC_EXE_ERR_SYSTEM -3
#define WC_EXE_ERR_OPENCL -4
#define WC_EXE_ERR_MPI -5
#define WC_EXE_ERR_INVALID_PARAMETER -6
#define WC_EXE_ERR_MISSING_CALLBACK -7
#define WC_EXE_ERR_INVALID_VALUE -8
#define WC_EXE_ERR_UNKNOWN INT_MIN

typedef int wc_err_t;

typedef struct wc_executor_details wc_exec_t;

typedef enum {
	WC_DEVTYPE_CPU,
	WC_DEVTYPE_GPU,
	WC_DEVTYPE_ANY
} wc_devtype_t;

typedef struct {
	void *ptr;
	uint32_t len; // to be safe from 32/64 bit mixed systems
} wc_data_t;

typedef struct {
	cl_device_id id;
	cl_device_type type;
	cl_uint address_bits;
	cl_uint compute_units;
	size_t workgroup_sz;
	cl_uint workitem_dim;
	size_t *workitem_sz;
	cl_ulong allocmem_sz;
	cl_ulong globalmem_sz;
	cl_ulong constmem_sz;
	cl_ulong localmem_sz;
	cl_command_queue cmdq; /* a command queue is per device */
	cl_context context; /* multiple devices can have same context */
	cl_program program; /* multiple devices can have same program */
} wc_cldev_t;

typedef struct {
	void *user;
	uint32_t max_devices;
	wc_devtype_t device_type;
	wc_err_t (*on_start)(const wc_exec_t *wc, void *user);
	wc_err_t (*on_finish)(const wc_exec_t *wc, void *user);
	char *(*get_code)(const wc_exec_t *wc, void *user, size_t *codelen);
	char *(*get_build_options)(const wc_exec_t *wc, void *user);
	void (*on_code_compile)(const wc_exec_t *wc, void *user, uint8_t success);

	uint64_t (*get_num_tasks)(const wc_exec_t *wc, void *user);
	uint32_t (*get_task_range_multiplier)(const wc_exec_t *wc, void *user);
	wc_err_t (*get_global_data)(const wc_exec_t *wc, void *user,
						wc_data_t *out);
	wc_err_t (*on_receive_global_data)(const wc_exec_t *wc, void *user,
						wc_data_t *gdata);

	wc_err_t (*on_device_start)(const wc_exec_t *wc, wc_cldev_t *dev,
						uint32_t devindex, void *user, const wc_data_t *gdata);
	wc_err_t (*on_device_finish)(const wc_exec_t *wc, wc_cldev_t *dev,
						uint32_t devindex, void *user, const wc_data_t *gdata);
	wc_err_t (*on_device_range_exec)(const wc_exec_t *wc, wc_cldev_t *dev,
						uint32_t devindex, void *user, const wc_data_t *gdata,
						uint64_t start, uint64_t end, cl_event *out_event);
	wc_err_t (*on_device_range_done)(const wc_exec_t *wc, wc_cldev_t *dev,
						uint32_t devindex, void *user, const wc_data_t *gdata,
						uint64_t start, uint64_t end);
	void (*free_global_data)(const wc_exec_t *wc, void *user,
						wc_data_t *gdata);
	void (*progress)(float percent, void *user);
} wc_exec_callbacks_t;

WCDLL wc_exec_t *wc_executor_init(int *argc, char ***argv);

WCDLL void wc_executor_destroy(wc_exec_t *wc);

WCDLL wc_err_t wc_executor_setup(wc_exec_t *wc, const wc_exec_callbacks_t *cbs);

WCDLL wc_err_t wc_executor_run(wc_exec_t *wc);

/* information providing functions */
WCDLL int wc_executor_num_systems(const wc_exec_t *wc);

WCDLL int wc_executor_system_id(const wc_exec_t *wc);

WCDLL uint64_t wc_executor_num_tasks(const wc_exec_t *wc);

/* number of devices in current system */
WCDLL uint32_t wc_executor_num_devices(const wc_exec_t *wc);

WCDLL void wc_executor_dump(const wc_exec_t *wc);



EXTERN_C_END

#endif //__WISECRACKER_EXECUTOR_H__

