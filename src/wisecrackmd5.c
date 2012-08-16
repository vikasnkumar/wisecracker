/*
 * Copyright: 2011. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 21st Dec 2011
 * Software: WiseCracker
 */
#include <wisecracker.h>
#ifdef WC_GETOPT_H
	#include <getopt.h>
#endif
#ifdef WC_OPENSSL_MD5_H
	#include <openssl/md5.h>
#endif
#ifndef MD5_DIGEST_LENGTH
	#define MD5_DIGEST_LENGTH 16
#endif

static unsigned char wc_md5_cl_code[] = {
	#include <md5_cl.h>
};
static const size_t wc_md5_cl_codelen = sizeof(wc_md5_cl_code);

struct wc_arguments {
	char *cl_filename;
	uint32_t max_devices;
	int verbose;
	int device_flag;
	uint32_t workitems;
	char *md5sum;
	char *prefix;
};

int wc_arguments_usage(const char *app)
{
	printf("\nUsage: %s [OPTIONS]\n", app);
	printf("\nOPTIONS are as follows:\n");
	printf("\t-h\t\tThis help message\n");
	printf("\t-v\t\tVerbose OpenCL compiler logs. Default is quiet.\n");
	printf("\t-f <filename>\tCustom OpenCL code to run. Optional.\n");
	printf("\t-m <value>\tMaximum devices to use. Default is 1\n");
	printf("\t-c\t\tUse CPU only if available. Default any.\n");
	printf("\t-g\t\tUse GPU only if available. Default any.\n");
	printf("\t-w <value>\tMaximum items for parallel execution for test run. "
			"Default 16\n");
	printf("\t-M <md5sum>\tMD5sum of an 8-char string in [A-Za-z0-9_$]\n");
	printf("\t-p <prefix>\tPrefix of the 8-char string whose MD5 sum we "
			"have. Needs the -M option as well.\n");
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
	args->max_devices = 1;
	args->verbose = 0;
	args->device_flag = WC_DEVICE_ANY;
	args->workitems = 16;
	args->md5sum = NULL;
	args->prefix = NULL;

	while ((opt = getopt(argc, argv, "hvgcm:f:w:M:p:")) != -1) {
		switch (opt) {
		case 'f':
			args->cl_filename = strdup(optarg);
			if (!args->cl_filename) {
				WC_ERROR_OUTOFMEMORY(strlen(optarg) + 1);
				rc = -1;
			}
			break;
		case 'm':
			args->max_devices = (uint32_t)strtol(optarg, NULL, 10);
			break;
		case 'v':
			args->verbose = 1;
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
		case 'M':
			/* each byte is represented as 2 characters */
			if (strlen(optarg) == (2 * MD5_DIGEST_LENGTH)) {
				args->md5sum = strdup(optarg);
				if (!args->md5sum) {
					WC_ERROR_OUTOFMEMORY(2 * MD5_DIGEST_LENGTH);
					rc = -1;
				}
			} else {
				WC_ERROR("Ignoring invalid MD5 sum: %s\n", optarg);
			}
			break;
		case 'p':
			args->prefix = strdup(optarg);
			if (!args->prefix) {
				WC_ERROR_OUTOFMEMORY(strlen(optarg));
				rc = -1;
			}
			break;
		case 'h':
		default:
			wc_arguments_usage(argv[0]);
			break;
		}
	}
	if (args->workitems < 1)
		args->workitems = 16;
	if ((args->prefix && !args->md5sum) || (args->md5sum && !args->prefix)) {
		WC_NULL("\n");
		WC_ERROR("You need both the prefix and the MD5 sum.\n");
		wc_arguments_usage(argv[0]);
		rc = -1;
	}
	return rc;
}

void wc_arguments_dump(const struct wc_arguments *args)
{
	if (args) {
		if (args->cl_filename)
			WC_INFO("OpenCL source code file: %s\n", args->cl_filename);
		WC_INFO("Max Devices to use: %u\n", args->max_devices);
		WC_INFO("Verbose OpenCL compiler logs: %s\n", args->verbose ? "yes" : "no");
		if (args->device_flag == WC_DEVICE_CPU)
			WC_INFO("CPU only\n");
		if (args->device_flag == WC_DEVICE_GPU)
			WC_INFO("GPU only\n");
		WC_INFO("Max Parallel Items: %u\n", args->workitems);
		if (args->md5sum)
			WC_INFO("Will check for MD5 sum: %s\n", args->md5sum);
		if (args->prefix)
			WC_INFO("Will use prefix: %s\n", args->prefix);
	}
}

void wc_arguments_cleanup(struct wc_arguments *args)
{
	if (args) {
		WC_FREE(args->cl_filename);
		WC_FREE(args->md5sum);
		WC_FREE(args->prefix);
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
	if (!wc_runtime_is_usable(wc))
		return -1;
	for (idx = 0; idx < wc->device_index; ++idx) {
		cl_mem input_mem = (cl_mem)0;
		cl_mem inputlen_mem = (cl_mem)0;
		cl_mem digest_mem = (cl_mem)0;
		cl_uchar *input = NULL;
		cl_uint *input_len = NULL;
		cl_uchar16 *digest = NULL;
		cl_kernel kernel = (cl_kernel)0;
		uint32_t jdx, argc;
		cl_uint l_bufsz = 0;
		cl_uint ilen = 0;
		wc_device_t *dev = &wc->devices[idx];

		ilen = maxblocksz * parallelsz;
		input = WC_MALLOC(ilen);
		assert(input != NULL);
		input_len = WC_MALLOC(sizeof(*input_len) * parallelsz);
		assert(input_len != NULL);
		memset(input, 0, ilen);
		memset(input_len, 0, sizeof(*input_len) * parallelsz);
		srand(time(NULL));
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
		l_bufsz = ilen;
		if (l_bufsz >= dev->localmem_sz) {
			WC_INFO("Size of local buffer: %u\n", l_bufsz);
			WC_ERROR("Local buffer max limit reached.\n");
			rc = -1;
			break;
		}
		do {
			struct timeval tv1, tv2;
			gettimeofday(&tv1, NULL);
			kernel = clCreateKernel(dev->program, "md5sum", &rc);
			WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
			input_mem = clCreateBuffer(dev->context, CL_MEM_READ_ONLY, ilen,
										NULL, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
			inputlen_mem = clCreateBuffer(dev->context, CL_MEM_READ_ONLY,
					sizeof(cl_uint) * parallelsz, NULL, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
			digest_mem = clCreateBuffer(dev->context, CL_MEM_READ_WRITE,
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
			gettimeofday(&tv2, NULL);
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

static const unsigned char wc_md5_decoder[0x80] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

int wc_md5_finder(wc_runtime_t *wc, const char *md5sum, const char *instr)
{
	cl_int rc = CL_SUCCESS;
	uint32_t idx;
	cl_ulong max_possibilities = 0;
	cl_uchar8 input;
	cl_uchar16 digest;
	size_t inlen = 0;
	if (!md5sum || !instr || !wc_runtime_is_usable(wc))
		return -1;
	if (strlen(md5sum) != (2 * MD5_DIGEST_LENGTH))
		return -1;
	inlen = strlen(instr);
	if (inlen >= 8) {
		WC_WARN("Input string is already complete. Max length accepted is 7\n");
		return -1;
	}
	max_possibilities = 8 - inlen;
	max_possibilities = 1 << (6 * (8 - inlen));
	WC_INFO("Max possibilities: %lu\n", max_possibilities);
	// copy the initial input
	memset(&input, 0, sizeof(input));
	for (idx = 0; idx < inlen; ++idx)
		input.s[idx] = (cl_uchar)instr[idx];
	// convert md5sum text to a digest
	memset(&digest, 0, sizeof(digest));
	for (idx = 0; idx < 2 * MD5_DIGEST_LENGTH; idx += 2)
		digest.s[idx >> 1] = (wc_md5_decoder[(int)md5sum[idx]] << 4) |
							wc_md5_decoder[(int)md5sum[idx + 1]];
	// for each device
	// check workgroup size and select number of parallel executions per kernel
	// invocation
	// check maximum number of kernel invocations needed
	//
	for (idx = 0; idx < wc->device_max; ++idx) {
		cl_kernel kernel = (cl_kernel)0;
		cl_mem matches_mem = (cl_mem)0;
		cl_uchar8 match;
		wc_device_t *dev = &wc->devices[idx];
		uint32_t max_kernel_calls = 0;
		const size_t localmem_per_kernel = 32; // local mem used per kernel call
		// max tries allowed based on local memory availability
		size_t max_ll_tries = dev->localmem_sz / localmem_per_kernel;
		cl_uint kdx;
		struct timeval tv1, tv2;
		// if the max parallel tries < max workgroups then use the max parallel
		// tries else use max workgroups
		max_ll_tries = (max_ll_tries < dev->workgroup_sz) ? max_ll_tries :
														dev->workgroup_sz;
		if (max_possibilities <= max_ll_tries) {
			max_kernel_calls = 1;
			max_ll_tries = max_possibilities;
		} else {
			max_kernel_calls = (max_possibilities / max_ll_tries) +
				((max_possibilities % max_ll_tries) ? 1 : 0);
		}
		WC_INFO("For device[%u] Max tries: %lu Kernel calls: %u\n", idx,
				max_ll_tries, max_kernel_calls);
		gettimeofday(&tv1, NULL);
		// create the kernel program and the buffers
		kernel = clCreateKernel(dev->program, "md5sumcheck8", &rc);
		WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
		matches_mem = clCreateBuffer(dev->context, CL_MEM_READ_WRITE,
				sizeof(cl_uchar8), NULL, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
		// invoke the kernel as many times as needed
		// check the matched output to see if anything worked in each kernel
		// call. break if it worked else continue.
		// cleanup memory and kernel code
		for (kdx = 0; kdx < max_kernel_calls; ++kdx) {
			const cl_uint workdim = 1;
			size_t local_work_size = 1;
			size_t global_work_size = max_ll_tries;
			cl_uint count = (cl_uint)max_ll_tries;
			uint32_t argc = 0;
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uchar8), &input);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uchar16), &digest);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_mem), &matches_mem);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uint), &count);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uint), &kdx);
			WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
			memset(&match, 0, sizeof(match));
			rc = clEnqueueWriteBuffer(dev->cmdq, matches_mem, CL_FALSE, 0,
					sizeof(cl_uchar8), &match, 0, NULL, NULL);
			WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
			rc = clEnqueueNDRangeKernel(dev->cmdq, kernel, workdim, NULL,
					&global_work_size, &local_work_size, 0, NULL, NULL);
			WC_ERROR_OPENCL_BREAK(clEnqueueNDRangeKernel, rc);
			rc = clEnqueueReadBuffer(dev->cmdq, matches_mem, CL_TRUE, 0,
					sizeof(cl_uchar8), &match, 0, NULL, NULL);
			WC_ERROR_OPENCL_BREAK(clEnqueueReadBuffer, rc);
			rc = clFlush(dev->cmdq);
			WC_ERROR_OPENCL_BREAK(clFlush, rc);
			if (match.s[0] != 0) {
				int8_t l = 0;
				gettimeofday(&tv2, NULL);
				WC_INFO("Found match in %uth kernel call: ", kdx);
				for (l = 0; l < 8; ++l)
					WC_NULL("%c", match.s[l]);
				WC_NULL("\n");
				WC_INFO("Time taken for finding match: %lfs\n",
						WC_TIME_TAKEN(tv1, tv2));
				break;
			}
		}
		if (match.s[0] == 0)
			WC_INFO("Unable to find a match.\n");
		if (kernel)
			rc |= clReleaseKernel(kernel);
		if (matches_mem)
			rc |= clReleaseMemObject(matches_mem);
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
	
	rc = wc_runtime_program_load(wc, (const char *)code, codelen, NULL,
								args.verbose);
	if (rc < 0)
		WC_ERROR("Unable to compile the source code from %s\n",
				args.cl_filename ? args.cl_filename : WC_MD5_CL);

	do {
		rc = wc_md5_testrun(wc, args.workitems);
		if (rc < 0) {
			WC_ERROR("Unable to execute the MD5 code.\n");
			break;
		}
		WC_INFO("Test run sucessful.\n");
		if (args.md5sum && args.prefix) {
			rc = wc_md5_finder(wc, args.md5sum, args.prefix);
			if (rc < 0) {
				WC_ERROR("Unable to verify MD5 sums.\n");
				break;
			}
		}
	} while (0);
	wc_runtime_destroy(wc);
	if (alloced)
		WC_FREE(code);
	wc_arguments_cleanup(&args);
	return 0;
}
