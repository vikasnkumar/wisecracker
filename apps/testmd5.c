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
 * Copyright: 2011-2012. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 17th October 2012
 * Software: WiseCracker
 */
#include <wisecracker.h>
#include <wisecracker/getopt.h>
#ifdef WC_OPENSSL_MD5_H
	#include <openssl/md5.h>
#else
	#error "This code needs openssl's header files"
#endif
#ifndef MD5_DIGEST_LENGTH
	#define MD5_DIGEST_LENGTH 16
#endif

#ifndef MAX_WORKITEMS
	#define MAX_WORKITEMS 128
#endif
#ifndef MAX_BLOCK_LEN
	#define MAX_BLOCK_LEN 512
#endif

static unsigned char wc_md5_cl_code[] = {
	#include <md5_cl.h>
};
static const size_t wc_md5_cl_codelen = sizeof(wc_md5_cl_code);
const char *wc_md5_cl_kernel = "wc_md5sum";

struct wc_user {
	char *cl_filename;
	uint32_t max_devices;
	wc_devtype_t device_type;
	uint64_t workitems;
	/* required for the task usage */
	struct wc_per_device {
		cl_kernel kernel;
		cl_mem input_mem;
		cl_mem inputlen_mem;
		cl_mem digest_mem;
		cl_uint parallelsz;
		cl_uint l_bufsz;
	} *devices;
	uint32_t num_devices;
	cl_uint *input_len;
	cl_uchar16 *digest;
};

int wc_user_usage(const char *app)
{
	printf("\nUsage: %s [OPTIONS]\n", app);
	printf("\nOPTIONS are as follows:\n");
	printf("\t-h\t\tThis help message\n");
	printf("\t-f <filename>\tCustom OpenCL code to run. Optional.\n");
	printf("\t-m <value>\tMaximum devices to use, 0 for all. Default is 0\n");
	printf("\t-c\t\tUse CPU only if available. Default any.\n");
	printf("\t-g\t\tUse GPU only if available. Default any.\n");
	printf("\t-w <value>\tMaximum items for parallel execution for test run. "
			"Default %u\n", MAX_WORKITEMS);
	printf("\n");
	exit(1);
}

int wc_user_parse(int argc, char **argv, struct wc_user *user)
{
	int opt = -1;
	int rc = 0;
	if (!argv || !user)
		return -1;
	user->cl_filename = NULL;
	user->max_devices = 0;
	user->device_type = WC_DEVTYPE_ANY;
	user->workitems = MAX_WORKITEMS;

	while ((opt = getopt(argc, argv, "hgcm:f:w:")) != -1) {
		switch (opt) {
		case 'f':
			user->cl_filename = wc_util_strdup(optarg);
			if (!user->cl_filename) {
				WC_ERROR_OUTOFMEMORY(strlen(optarg) + 1);
				rc = -1;
			}
			break;
		case 'm':
			user->max_devices = (uint32_t)strtol(optarg, NULL, 10);
			break;
		case 'c':
			user->device_type = WC_DEVTYPE_CPU;
			break;
		case 'g':
			user->device_type = WC_DEVTYPE_GPU;
			break;
		case 'w':
			user->workitems = (uint64_t)strtol(optarg, NULL, 10);
			break;
		case 'h':
		default:
			wc_user_usage(argv[0]);
			break;
		}
	}
	if (user->workitems < 1)
		user->workitems = MAX_WORKITEMS;
	return rc;
}

void wc_user_dump(const struct wc_user *user)
{
	if (user) {
		if (user->cl_filename)
			WC_INFO("OpenCL source code file: %s\n", user->cl_filename);
		if (user->max_devices)
			WC_INFO("Max Devices to use: %u\n", user->max_devices);
		else
			WC_INFO("Max Devices to use: all available\n");
		if (user->device_type == WC_DEVTYPE_CPU)
			WC_INFO("CPU only\n");
		if (user->device_type == WC_DEVTYPE_GPU)
			WC_INFO("GPU only\n");
		WC_INFO("Max Parallel Items: %lu\n", user->workitems);
	}
}

void wc_user_cleanup(struct wc_user *user)
{
	if (user) {
		WC_FREE(user->cl_filename);
		WC_FREE(user->devices);
		WC_FREE(user->input_len);
		WC_FREE(user->digest);
	}
}

int wc_md5_compare(const cl_uchar *d1, const cl_uchar16 *d2)
{
	int fail = 1;
	if (d1 && d2) {
		int i = 0;
		fail = 0;
		for (i = 0; i < 16; ++i) {
			if (d1[i] != d2->s[i]) {
				fail = 1;
				break;
			}
		}
		if (fail) {
			WC_INFO("Expected: ");
			for (i = 0; i < 16; ++i)
				WC_NULL("%02x", d1[i]);
			WC_NULL("\n");
			WC_INFO("Calculated: ");
			for (i = 0; i < 16; ++i)
				WC_NULL("%02x", d2->s[i]);
			WC_NULL("\n");
		}
	}
	return fail;
}

wc_err_t testmd5_on_start(const wc_exec_t *wc, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	if (wcu) {
		const size_t wcpdsz = sizeof(struct wc_per_device);
		WC_DEBUG("In on_start callback, allocating stuff\n");
		// just print something for now
		wc_user_dump(wcu);
		wcu->num_devices = wc_executor_num_devices(wc);
		if (wcu->num_devices == 0) {
			WC_DEBUG("No devices found on system\n");
			return WC_EXE_ERR_OPENCL;
		}
		wcu->devices = WC_MALLOC(wcu->num_devices * wcpdsz);
		if (!wcu->devices) {
			wcu->num_devices = 0;
			WC_ERROR_OUTOFMEMORY(wcu->num_devices * wcpdsz);
			return WC_EXE_ERR_OUTOFMEMORY;
		}
		memset(wcu->devices, 0, wcu->num_devices * wcpdsz);
		wcu->input_len = WC_MALLOC(wcu->workitems * sizeof(cl_uint));
		if (wcu->input_len) {
			cl_uint idx;
			for (idx = 0; idx < wcu->workitems; ++idx)
				wcu->input_len[idx] = MAX_BLOCK_LEN;
		} else {
			WC_ERROR_OUTOFMEMORY(wcu->workitems * sizeof(cl_uint));
			return WC_EXE_ERR_OUTOFMEMORY;
		}
		wcu->digest = WC_MALLOC(wcu->workitems * sizeof(cl_uchar16));
		if (!wcu->digest) {
			WC_ERROR_OUTOFMEMORY(wcu->workitems * sizeof(cl_uchar16));
			return WC_EXE_ERR_OUTOFMEMORY;
		}
		memset(wcu->digest, 0, sizeof(cl_uchar16) * wcu->workitems);
	} else {
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	return WC_EXE_OK;
}

wc_err_t testmd5_on_finish(const wc_exec_t *wc, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	if (wcu) {
		WC_DEBUG("In on_finish callback.\n");
		WC_FREE(wcu->devices);
		wcu->num_devices = 0;
		WC_FREE(wcu->input_len);
		WC_FREE(wcu->digest);
	} else {
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	return WC_EXE_OK;
}

void testmd5_on_compile(const wc_exec_t *wc, void *user, uint8_t success)
{
	if (success) {
		WC_DEBUG("Code has been compiled successfully\n");
	} else {
		WC_DEBUG("Code failed to compile\n");
	}
}

char *testmd5_get_code(const wc_exec_t *wc, void *user, size_t *codelen)
{
	unsigned char *code = NULL;
	struct wc_user *wcu = (struct wc_user *)user;
	size_t clen = 0;
	if (wcu && wcu->cl_filename) {
		int rc = wc_util_glob_file(wcu->cl_filename, &code, &clen);
		if (rc < 0 || !code || clen < 1) {
			WC_ERROR("Unable to load code from %s\n", wcu->cl_filename);
			return NULL;
		}
		WC_INFO("Using custom code from %s\n", wcu->cl_filename);
		if (codelen)
			*codelen = clen;
	} else {
		code = WC_MALLOC(wc_md5_cl_codelen + 1);
		if (!code) {
			WC_ERROR_OUTOFMEMORY(wc_md5_cl_codelen + 1);
			return NULL;
		}
		memcpy(code, wc_md5_cl_code, wc_md5_cl_codelen);
		code[wc_md5_cl_codelen] = 0x0; // terminating NULL
		if (codelen)
			*codelen = wc_md5_cl_codelen;
		WC_INFO("Using built-in code from %s\n", WC_MD5_CL);
	}
	assert(code != NULL);
	assert(*codelen > 0);
	return (char *)code;
}

uint64_t testmd5_get_num_tasks(const wc_exec_t *wc, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	return (wcu) ? wcu->workitems : 0;
}

wc_err_t testmd5_get_global_data(const wc_exec_t *wc, void *user,
								wc_data_t *out)
{
	struct wc_user *wcu = (struct wc_user *)user;
	const cl_uint maxblocksz = MAX_BLOCK_LEN;
	cl_uint ilen = 0;
	cl_uint idx;
	cl_uchar *input = NULL;
	if (!wcu || !out)
		return WC_EXE_ERR_INVALID_PARAMETER;
	// initialize the variables
	ilen = maxblocksz * (cl_uint)wcu->workitems;
	input = WC_MALLOC(ilen);
	if (!input)
		return WC_EXE_ERR_OUTOFMEMORY;
	memset(input, 0, ilen);
	srand((int)time(NULL));
	// randomly fill the buffers
	for (idx = 0; idx < wcu->workitems ; ++idx) {
		cl_uint kdx;
		for (kdx = 0; kdx < maxblocksz; ++kdx) {
			input[kdx + idx * maxblocksz] = (cl_uchar)(rand() & 0xFF);
		}
	}
	out->ptr = input;
	out->len = ilen;
	return WC_EXE_OK;
}

wc_err_t testmd5_on_device_start(const wc_exec_t *wc, wc_cldev_t *dev,
								uint32_t devindex, void *user,
								wc_data_t *gdata)
{
	cl_int rc = CL_SUCCESS;
	struct wc_user *wcu = (struct wc_user *)user;
	if (!wc || !dev || !wcu || !gdata || !gdata->ptr)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!wcu->devices || devindex >= wcu->num_devices)
		return WC_EXE_ERR_BAD_STATE;
	do {
		const cl_uint maxblocksz = MAX_BLOCK_LEN;
		cl_uint ilen;
		cl_uint argc = 0;
		cl_ulong localmem_per_kernel = 0;
		cl_uint parallelsz = (cl_uint)wc_executor_num_tasks(wc);
		struct wc_per_device *wcd = &wcu->devices[devindex];

		ilen = maxblocksz * parallelsz;
		memset(wcd, 0, sizeof(*wcd));
		wcd->parallelsz = parallelsz;
		wcd->l_bufsz = ilen;
		wcd->kernel = clCreateKernel(dev->program, wc_md5_cl_kernel, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
		wcd->input_mem = clCreateBuffer(dev->context, CL_MEM_READ_ONLY,
										gdata->len, NULL, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
		wcd->inputlen_mem = clCreateBuffer(dev->context, CL_MEM_READ_ONLY,
								sizeof(cl_uint) * wcu->workitems, NULL, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
		wcd->digest_mem = clCreateBuffer(dev->context, CL_MEM_READ_WRITE,
									sizeof(cl_uchar16) * parallelsz, NULL, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);

		rc = clGetKernelWorkGroupInfo(wcd->kernel, dev->id,
				CL_KERNEL_LOCAL_MEM_SIZE, sizeof(cl_ulong),
				&localmem_per_kernel, NULL);
		WC_ERROR_OPENCL_BREAK(clGetKernelWorkGroupInfo, rc);
		WC_DEBUG("Local mem per kernel: %lu for device %u\n",
				localmem_per_kernel, devindex);
		wcd->l_bufsz = (cl_uint)localmem_per_kernel + 2 * maxblocksz;
		argc = 0;
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_mem), &wcd->input_mem);
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_mem), &wcd->inputlen_mem);
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_mem), &wcd->digest_mem);
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_uint), &wcd->parallelsz);
		rc |= clSetKernelArg(wcd->kernel, argc++, wcd->l_bufsz, NULL);
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_uint), &wcd->l_bufsz);
		WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
	} while (0);
	return (rc != CL_SUCCESS) ? WC_EXE_ERR_OPENCL : WC_EXE_OK;
}

wc_err_t testmd5_on_device_range_exec(const wc_exec_t *wc, wc_cldev_t *dev,
								uint32_t devindex, void *user,
								wc_data_t *gdata,
								uint64_t start, uint64_t end,
								cl_event *outevent)
{
	cl_int rc = CL_SUCCESS;
	struct wc_user *wcu = (struct wc_user *)user;
	if (!wc || !dev || !wcu || !gdata || !gdata->ptr)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!wcu->devices || devindex >= wcu->num_devices || !wcu->input_len)
		return WC_EXE_ERR_BAD_STATE;
	do {
		const cl_uint workdim = 1;
		size_t local_work_size = 1;
		size_t global_work_size = end - start;
		size_t global_work_offset = start;
		struct wc_per_device *wcd = &wcu->devices[devindex];
		rc = clEnqueueWriteBuffer(dev->cmdq, wcd->input_mem, CL_FALSE, 0,
				gdata->len, gdata->ptr, 0, NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
		rc = clEnqueueWriteBuffer(dev->cmdq, wcd->inputlen_mem, CL_FALSE, 0,
				sizeof(cl_uint) * wcu->workitems, wcu->input_len, 0, NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
		WC_INFO("Global work size: %lu\n", global_work_size);
		rc = clEnqueueNDRangeKernel(dev->cmdq, wcd->kernel, workdim,
				&global_work_offset, &global_work_size, &local_work_size, 0,
				NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueNDRangeKernel, rc);
		// here we force the wait and check results.
		rc = clEnqueueReadBuffer(dev->cmdq, wcd->digest_mem, CL_TRUE, 0,
				sizeof(cl_uchar16) * wcu->workitems, wcu->digest, 0, NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueReadBuffer, rc);
		if (rc == CL_SUCCESS) {
			uint32_t jdx;
			cl_uchar *input = (cl_uchar *)gdata->ptr;
			const int maxblocksz = MAX_BLOCK_LEN;
			for (jdx = 0; jdx < wcu->workitems; ++jdx) {
				cl_uchar md[MD5_DIGEST_LENGTH];
				memset(md, 0, sizeof(md));
				MD5(&input[jdx * maxblocksz], wcu->input_len[jdx], md);
				if (wc_md5_compare(md, &wcu->digest[jdx])) {
					break;
				}
			}
		}
	} while (0);
	return (rc != CL_SUCCESS) ? WC_EXE_ERR_OPENCL : WC_EXE_OK;
}

wc_err_t testmd5_on_device_finish(const wc_exec_t *wc, wc_cldev_t *dev,
								uint32_t devindex, void *user,
								wc_data_t *gdata)
{
	cl_int rc = CL_SUCCESS;
	struct wc_user *wcu = (struct wc_user *)user;
	struct wc_per_device *wcd = NULL;
	if (!wc || !dev || !wcu)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!wcu->devices || devindex >= wcu->num_devices)
		return WC_EXE_ERR_BAD_STATE;
	wcd = &wcu->devices[devindex];
	if (wcd->kernel)
		rc |= clReleaseKernel(wcd->kernel);
	if (wcd->input_mem)
		rc |= clReleaseMemObject(wcd->input_mem);
	if (wcd->inputlen_mem)
		rc |= clReleaseMemObject(wcd->inputlen_mem);
	if (wcd->digest_mem)
		rc |= clReleaseMemObject(wcd->digest_mem);
	memset(wcd, 0, sizeof(*wcd));
	return (rc != CL_SUCCESS) ? WC_EXE_ERR_OPENCL : WC_EXE_OK;
}

void testmd5_progress(float percent, void *user)
{
	WC_INFO("Progress: %0.02f\n", percent);
}

int main(int argc, char **argv)
{
	wc_err_t err = WC_EXE_OK;
	struct wc_user user;
	wc_exec_t *wc = NULL;
	wc_exec_callbacks_t callbacks;
	// print license
	WC_NULL("%s\n", wc_util_license());
	// create executor object. if MPI is used, parse out the MPI arguments
	wc = wc_executor_init(&argc, &argv);
	assert(wc != NULL);
	do {
		struct timeval tv1, tv2;
		wc_util_timeofday(&tv1);
		// if we are the main application, then we parse the arguments
		if (wc_executor_system_id(wc) == 0) {
			// parse actual commandline arguments
			memset(&user, 0, sizeof(user));
			if (wc_user_parse(argc, argv, &user) < 0) {
				WC_ERROR("Unable to parse arguments.\n");
				return -1;
			}
		}
		// set up the callbacks for distribution
		memset(&callbacks, 0, sizeof(callbacks));
		callbacks.user = &user;
		callbacks.max_devices = user.max_devices;
		callbacks.device_type = user.device_type;
		callbacks.on_start = testmd5_on_start;
		callbacks.on_finish = testmd5_on_finish;
		callbacks.get_code = testmd5_get_code;
		callbacks.get_num_tasks = testmd5_get_num_tasks;
		callbacks.on_code_compile = testmd5_on_compile;
		callbacks.get_global_data = testmd5_get_global_data;
		callbacks.on_device_start = testmd5_on_device_start;
		callbacks.on_device_finish = testmd5_on_device_finish;
		callbacks.on_device_range_exec = testmd5_on_device_range_exec;
		callbacks.progress = testmd5_progress;
		err = wc_executor_setup(wc, &callbacks);
		assert(err == WC_EXE_OK);
		if (err != WC_EXE_OK) {
			WC_ERROR("Error setting up callbacks: %d\n", err);
			break;
		}
		// print information of the executor object on screen
		wc_executor_dump(wc);
		err = wc_executor_run(wc, 0);
		if (err != WC_EXE_OK) {
			WC_ERROR("Unable to execute the MD5 code: %d\n", err);
			break;
		} else {
			wc_util_timeofday(&tv2);
			WC_INFO("Test run sucessful.\n");
			WC_INFO("Time taken for test run: %lf seconds\n",
					WC_TIME_TAKEN(tv1, tv2));
		}
	} while (0);
	wc_executor_destroy(wc);
	wc_user_cleanup(&user);
	return (int)err;
}
