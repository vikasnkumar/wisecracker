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
 * Date: 21st Dec 2011
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

static unsigned char wc_md5_cl_code[] = {
	#include <md5_cl.h>
};
static const size_t wc_md5_cl_codelen = sizeof(wc_md5_cl_code);
const char *wc_md5_cl_kernel = "wc_md5sum";

struct wc_arguments {
	char *cl_filename;
	uint32_t max_devices;
	int device_flag;
	uint32_t workitems;
};

int wc_arguments_usage(const char *app)
{
	printf("\nUsage: %s [OPTIONS]\n", app);
	printf("\nOPTIONS are as follows:\n");
	printf("\t-h\t\tThis help message\n");
	printf("\t-f <filename>\tCustom OpenCL code to run. Optional.\n");
	printf("\t-m <value>\tMaximum devices to use, 0 for all. Default is 0\n");
	printf("\t-c\t\tUse CPU only if available. Default any.\n");
	printf("\t-g\t\tUse GPU only if available. Default any.\n");
	printf("\t-w <value>\tMaximum items for parallel execution for test run. "
			"Default 16\n");
	printf("\n");
	exit(1);
}

int wc_arguments_parse(int argc, char **argv, struct wc_arguments *args)
{
	int opt = -1;
	int rc = 0;
	if (!argv || !args)
		return -1;
	args->cl_filename = NULL;
	args->max_devices = 0;
	args->device_flag = WC_DEVICE_ANY;
	args->workitems = 16;

	while ((opt = getopt(argc, argv, "hgcm:f:w:")) != -1) {
		switch (opt) {
		case 'f':
			args->cl_filename = wc_util_strdup(optarg);
			if (!args->cl_filename) {
				WC_ERROR_OUTOFMEMORY(strlen(optarg) + 1);
				rc = -1;
			}
			break;
		case 'm':
			args->max_devices = (uint32_t)strtol(optarg, NULL, 10);
			break;
		case 'c':
			args->device_flag = WC_DEVICE_CPU;
			break;
		case 'g':
			args->device_flag = WC_DEVICE_GPU;
			break;
		case 'w':
			args->workitems = (uint32_t)strtol(optarg, NULL, 10);
			break;
		case 'h':
		default:
			wc_arguments_usage(argv[0]);
			break;
		}
	}
	if (args->workitems < 1)
		args->workitems = 16;
	return rc;
}

void wc_arguments_dump(const struct wc_arguments *args)
{
	if (args) {
		if (args->cl_filename)
			WC_INFO("OpenCL source code file: %s\n", args->cl_filename);
		if (args->max_devices)
			WC_INFO("Max Devices to use: %u\n", args->max_devices);
		else
			WC_INFO("Max Devices to use: all available\n");
		if (args->device_flag == WC_DEVICE_CPU)
			WC_INFO("CPU only\n");
		if (args->device_flag == WC_DEVICE_GPU)
			WC_INFO("GPU only\n");
		WC_INFO("Max Parallel Items: %u\n", args->workitems);
	}
}

void wc_arguments_cleanup(struct wc_arguments *args)
{
	if (args) {
		WC_FREE(args->cl_filename);
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

int wc_md5_testrun(wc_runtime_t *wc, cl_uint parallelsz)
{
	cl_int rc = CL_SUCCESS;
	const cl_uint maxblocksz = 512;
	const cl_uint workdim = 1;
	size_t local_work_size = 1;
	size_t global_work_size = parallelsz;
	uint32_t idx;
	cl_uint ilen = 0;
	cl_uint l_bufsz = 0;
	if (!wc_runtime_is_usable(wc))
		return -1;
	ilen = maxblocksz * parallelsz;
	l_bufsz = ilen;
	WC_INFO("We test the program per device\n");
	for (idx = 0; idx < wc->device_max; ++idx) {
		cl_mem input_mem = (cl_mem)0;
		cl_mem inputlen_mem = (cl_mem)0;
		cl_mem digest_mem = (cl_mem)0;
		cl_uchar *input = NULL;
		cl_uint *input_len = NULL;
		cl_uchar16 *digest = NULL;
		cl_kernel kernel = (cl_kernel)0;
		uint32_t jdx, argc;
		wc_device_t *dev = &wc->devices[idx];

		input = WC_MALLOC(ilen);
		assert(input != NULL);
		input_len = WC_MALLOC(sizeof(*input_len) * parallelsz);
		assert(input_len != NULL);
		memset(input, 0, ilen);
		memset(input_len, 0, sizeof(*input_len) * parallelsz);
		srand((int)time(NULL));
		// randomly fill the buffers
		for (jdx = 0; jdx < parallelsz; ++jdx) {
			uint32_t kdx;
			input_len[jdx] = maxblocksz;
			for (kdx = 0; kdx < input_len[jdx]; ++kdx) {
				input[kdx + jdx * maxblocksz] = (cl_uchar)(rand() & 0xFF);
			}
		}
		digest = WC_MALLOC(sizeof(cl_uchar16) * parallelsz);
		assert(digest != NULL);
		memset(digest, 0, sizeof(cl_uchar16) * parallelsz);
		if (l_bufsz >= dev->localmem_sz) {
			WC_INFO("Size of local buffer: %u\n", l_bufsz);
			WC_ERROR("Local buffer max limit reached.\n");
			rc = -1;
			break;
		}
		do {
			struct timeval tv1, tv2;
			wc_platform_t *plat = NULL;
			if (dev->pl_index < wc->platform_max) {
				plat = &wc->platforms[dev->pl_index];
			} else {
				rc = -1;
				break;
			}
			wc_util_timeofday(&tv1);
			kernel = clCreateKernel(plat->program, wc_md5_cl_kernel, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
			input_mem = clCreateBuffer(plat->context, CL_MEM_READ_ONLY, ilen,
										NULL, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
			inputlen_mem = clCreateBuffer(plat->context, CL_MEM_READ_ONLY,
					sizeof(cl_uint) * parallelsz, NULL, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
			digest_mem = clCreateBuffer(plat->context, CL_MEM_READ_WRITE,
									sizeof(cl_uchar16) * parallelsz, NULL, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
			argc = 0;
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_mem), &input_mem);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_mem), &inputlen_mem);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_mem), &digest_mem);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uint), &parallelsz);
			rc |= clSetKernelArg(kernel, argc++, l_bufsz, NULL);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uint), &l_bufsz);
			WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
			rc = clEnqueueWriteBuffer(dev->cmdq, input_mem, CL_FALSE, 0, ilen,
					input, 0, NULL, NULL);
			WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
			rc = clEnqueueWriteBuffer(dev->cmdq, inputlen_mem, CL_FALSE, 0,
					sizeof(cl_uint) * parallelsz, input_len, 0, NULL, NULL);
			WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
			rc = clEnqueueNDRangeKernel(dev->cmdq, kernel, workdim, NULL,
					&global_work_size, &local_work_size, 0, NULL, NULL);
			WC_ERROR_OPENCL_BREAK(clEnqueueNDRangeKernel, rc);
			rc = clEnqueueReadBuffer(dev->cmdq, digest_mem, CL_TRUE, 0,
					sizeof(cl_uchar16) * parallelsz, digest, 0, NULL, NULL);
			WC_ERROR_OPENCL_BREAK(clEnqueueReadBuffer, rc);
			wc_util_timeofday(&tv2);
			WC_INFO("Time taken for test run: %lf\n", WC_TIME_TAKEN(tv1, tv2));
		} while (0);
		rc |= clFlush(dev->cmdq);
		if (kernel)
			rc |= clReleaseKernel(kernel);
		if (input_mem)
			rc |= clReleaseMemObject(input_mem);
		if (inputlen_mem)
			rc |= clReleaseMemObject(inputlen_mem);
		if (digest_mem)
			rc |= clReleaseMemObject(digest_mem);
		if (rc == CL_SUCCESS) {
			for (jdx = 0; jdx < parallelsz; ++jdx) {
				cl_uchar md[MD5_DIGEST_LENGTH];
				memset(md, 0, sizeof(md));
				MD5(&input[jdx * maxblocksz], input_len[jdx], md);
				if (wc_md5_compare(md, &digest[jdx])) {
					break;	
				}
			}
		}
		WC_FREE(input);
		WC_FREE(input_len);
		WC_FREE(digest);
	}

	return (rc == CL_SUCCESS) ? 0 : -1;
}

int main(int argc, char **argv)
{
	wc_runtime_t *wc = NULL;
	unsigned char *code = NULL;
	size_t codelen = 0;
	int rc = 0;
	uint8_t alloced = 0;
	struct wc_arguments args;

	WC_NULL("%s\n", wc_util_license());
	memset(&args, 0, sizeof(args));
	if (wc_arguments_parse(argc, argv, &args) < 0) {
		WC_ERROR("Unable to parse arguments.\n");
		return -1;
	}
	wc_arguments_dump(&args);
	if (args.cl_filename) {
		rc = wc_util_glob_file(args.cl_filename, &code, &codelen);
		if (rc < 0 || !code || codelen < 1) {
			WC_ERROR("Unable to load code from %s\n", args.cl_filename);
			wc_arguments_cleanup(&args);
			return -1;
		}
		WC_INFO("Using custom code from %s\n", args.cl_filename);
		alloced = 1;
	} else {
		code = wc_md5_cl_code;
		codelen = wc_md5_cl_codelen;
		alloced = 0;
		WC_INFO("Using built-in code from %s\n", WC_MD5_CL);
	}
	assert(code != NULL);
	assert(codelen > 0);

	wc = wc_runtime_create(args.device_flag, args.max_devices);
	assert(wc != NULL);
	wc_runtime_dump(wc);

	do {
		rc = wc_runtime_program_load(wc, (const char *)code, codelen, NULL);
		if (rc < 0) {
			WC_ERROR("Unable to compile the source code from %s\n",
					args.cl_filename ? args.cl_filename : WC_MD5_CL);
			break;
		}
		rc = wc_md5_testrun(wc, args.workitems);
		if (rc < 0) {
			WC_ERROR("Unable to execute the MD5 code.\n");
			break;
		} else {
			WC_INFO("Test run sucessful.\n");
			rc = 0;
		}
	} while (0);

	wc_runtime_destroy(wc);
	if (alloced)
		WC_FREE(code);
	wc_arguments_cleanup(&args);
	return rc;
}
