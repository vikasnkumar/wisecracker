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

#ifndef MD5_DIGEST_LENGTH
	#define MD5_DIGEST_LENGTH 16
#endif

static unsigned char wc_md5_cl_code[] = {
	#include <md5_cl.h>
};
static const size_t wc_md5_cl_codelen = sizeof(wc_md5_cl_code);
const char *wc_md5_cl_kernel = "wc_md5sum_check_8";

struct wc_arguments {
	char *cl_filename;
	uint32_t max_devices;
	int device_flag;
	wc_util_charset_t charset;
	uint8_t nchars; // a single byte can have values 0-255
	char *md5sum;
	char *prefix;
};

int wc_arguments_usage(const char *app)
{
	printf("\nUsage: %s [OPTIONS]\n", app);
	printf("\nOPTIONS are as follows:\n");
	printf("\n\t-h\t\tThis help message\n");
	printf("\n\t-f <filename>\tCustom OpenCL code to run. Optional.\n");
	printf("\n\t-m <value>\tMaximum devices to use. Default is 1\n");
	printf("\n\t-c\t\tUse CPU only if available. Default any.\n");
	printf("\n\t-g\t\tUse GPU only if available. Default any.\n");
	printf("\n\t-N <number>\tLength of string to look for. Default is 8.\n");
	printf("\n\t-M <md5sum>\tMD5sum of an N-char string in a given charset\n");
	printf("\n\t-p <prefix>\tSuggested prefix of the N-char string whose MD5"
			" sum\n\t\t\twe want to crack. Needs the -M option as well.\n");
	printf("\n\t-C <charset>\tAny of the below character sets to use for "
			"cracking:\n\t\t\t%s - [A-Za-z0-9] (default)\n"
			"\t\t\t%s - [A-Za-z]\n"
			"\t\t\t%s - [0-9]\n"
			"\t\t\t%s - ~!@#$%%^&*()_+=-|[]{}`\\;:'\",<>./?\n"
			"\t\t\t%s - alpha and digit and special together\n",
			wc_util_charset_tostring(WC_UTIL_CHARSET_ALNUM),
			wc_util_charset_tostring(WC_UTIL_CHARSET_ALPHA),
			wc_util_charset_tostring(WC_UTIL_CHARSET_DIGIT),
			wc_util_charset_tostring(WC_UTIL_CHARSET_SPECIAL),
			wc_util_charset_tostring(WC_UTIL_CHARSET_ALNUMSPL));
	printf("\n");
	exit(1);
}

int wc_arguments_parse(int argc, char **argv, struct wc_arguments *args)
{
	int opt = -1;
	int rc = 0;
	const char *appname = NULL;
	if (!argv || !args)
		return -1;
	args->cl_filename = NULL;
	args->max_devices = 1;
	args->device_flag = WC_DEVICE_ANY;
	args->charset = WC_UTIL_CHARSET_ALNUM;
	args->nchars = 8;
	args->md5sum = NULL;
	args->prefix = NULL;
	appname = WC_BASENAME(argv[0]);
	while ((opt = getopt(argc, argv, "hgcm:f:M:p:C:N:")) != -1) {
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
		case 'M':
			/* each byte is represented as 2 characters */
			if (strlen(optarg) == (2 * MD5_DIGEST_LENGTH)) {
				args->md5sum = wc_util_strdup(optarg);
				if (!args->md5sum) {
					WC_ERROR_OUTOFMEMORY(2 * MD5_DIGEST_LENGTH);
					rc = -1;
				}
			} else {
				WC_ERROR("Ignoring invalid MD5 sum: %s\n", optarg);
			}
			break;
		case 'p':
			args->prefix = wc_util_strdup(optarg);
			if (!args->prefix) {
				WC_ERROR_OUTOFMEMORY(strlen(optarg));
				rc = -1;
			}
			break;
		case 'C':
			if (WC_STRCMPI(optarg, "alnum") == 0) {
				args->charset = WC_UTIL_CHARSET_ALNUM;
			} else if (WC_STRCMPI(optarg, "alpha") == 0) {
				args->charset = WC_UTIL_CHARSET_ALPHA;
			} else if (WC_STRCMPI(optarg, "alnumspl") == 0) {
				args->charset = WC_UTIL_CHARSET_ALNUMSPL;
			} else if (WC_STRCMPI(optarg, "digit") == 0) {
				args->charset = WC_UTIL_CHARSET_DIGIT;
			} else if (WC_STRCMPI(optarg, "special") == 0) {
				args->charset = WC_UTIL_CHARSET_SPECIAL;
			} else {
				WC_WARN("Unknown charset %s given. Using the default.\n",
						optarg);
			}
			break;
		case 'N':
			args->nchars = (uint8_t)strtol(optarg, NULL, 10);
			if (args->nchars < 1) {
				WC_ERROR("Invalid no. of characters given: %s.\n", optarg);
				rc = -1;
			} else if (args->nchars > 8) {
				WC_ERROR("%s does not support more than 8 characters.\n",
						appname);
				rc = -1;
			}
			break;
		case 'h':
		default:
			wc_arguments_usage(appname);
			break;
		}
	}
	if (!args->md5sum) {
		WC_NULL("\n");
		WC_ERROR("You need to provide an MD5 sum to crack.\n");
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
		if (args->device_flag == WC_DEVICE_CPU)
			WC_INFO("CPU only\n");
		if (args->device_flag == WC_DEVICE_GPU)
			WC_INFO("GPU only\n");
		WC_INFO("No. of chars: %u\n", args->nchars);
		WC_INFO("Charset: %s\n", wc_util_charset_tostring(args->charset));
		if (args->md5sum)
			WC_INFO("Will try to crack MD5 sum: %s\n", args->md5sum);
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

cl_ulong wc_md5_possibilities(wc_util_charset_t chs, uint8_t nchars)
{
	cl_ulong result = 1;
	cl_ulong chsz = wc_util_charset_size(chs);
	// calculate chsz ^ nchars here
	while (nchars) {
		if (nchars & 1)
			result *= chsz;
		nchars >>= 1;
		chsz *= chsz;
	}
	return result;
}

char *wc_md5_create_buildopts(uint8_t nchars)
{
	if (nchars >= 1 && nchars <= 8) {
		char *buildopts = WC_MALLOC(256);
		if (buildopts) {
			snprintf(buildopts, 256, "-DWC_MD5_CRACK_SIZE=%d", (int)nchars);
			return buildopts;
		} else {
			WC_ERROR_OUTOFMEMORY(256);
		}
	}
	return NULL;
}

int wc_md5_checker(wc_runtime_t *wc, const char *md5sum, const char *prefix,
		wc_util_charset_t charset, uint8_t nchars)
{
	cl_int rc = CL_SUCCESS;
	uint32_t idx;
	cl_ulong max_possibilities = 0;
	cl_uchar8 input;
	cl_uchar16 digest;
	size_t pfxlen = 0;
	cl_ulong charset_sz = wc_util_charset_size(charset);
	if (!md5sum || !wc_runtime_is_usable(wc) || (nchars < 1))
		return -1;
	if (strlen(md5sum) != (2 * MD5_DIGEST_LENGTH))
		return -1;
	pfxlen = prefix ? strlen(prefix) : 0;
	if (pfxlen >= nchars) {
		WC_WARN("Input string is already complete. Max length accepted is %d\n",
				(int)nchars);
		return -1;
	}
	nchars -= (uint8_t)pfxlen;
	max_possibilities = wc_md5_possibilities(charset, nchars);
	if (max_possibilities == 0) {
		WC_WARN("Max possibilities was calculated to be 0 for %s of %d chars\n",
				wc_util_charset_tostring(charset), (int)nchars);
		return -1;
	}
	WC_INFO("Max possibilities: %lu\n", (unsigned long)max_possibilities);
	// copy the initial input
	memset(&input, 0, sizeof(input));
	for (idx = 0; idx < pfxlen; ++idx)
		input.s[idx] = (cl_uchar)prefix[idx];
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
		cl_ulong max_kernel_calls = 0;
		const size_t localmem_per_kernel = 32; // local mem used per kernel call
		// max tries allowed based on local memory availability
		size_t parallel_tries = dev->localmem_sz / localmem_per_kernel;
		cl_ulong kdx;
		struct timeval tv1, tv2;
		float progress;
		double ttinterval = -1.0;
		// if the max parallel tries < max workgroups then use the max parallel
		// tries else use max workgroups
		if ((parallel_tries > (dev->workgroup_sz * dev->compute_units)))
			parallel_tries = (dev->workgroup_sz * dev->compute_units);
		if (max_possibilities <= parallel_tries) {
			max_kernel_calls = 1;
			parallel_tries = max_possibilities;
		} else {
			// find the ceiling maximum number of kernel calls needed
			max_kernel_calls = (cl_ulong)(max_possibilities / parallel_tries) +
				((max_possibilities % parallel_tries) ? 1 : 0);
		}
		WC_INFO("For device[%u] Parallel tries: %lu Kernel calls: %lu\n", idx,
				parallel_tries, (unsigned long)max_kernel_calls);
		wc_util_timeofday(&tv1);
		// create the kernel program and the buffers
		kernel = clCreateKernel(dev->program, wc_md5_cl_kernel, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
		matches_mem = clCreateBuffer(dev->context, CL_MEM_READ_WRITE,
				sizeof(cl_uchar8), NULL, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
		// invoke the kernel as many times as needed
		// check the matched output to see if anything worked in each kernel
		// call. break if it worked else continue.
		// cleanup memory and kernel code
		progress = 0.0;
		for (kdx = 0; kdx < max_kernel_calls; kdx += charset_sz) {
			const cl_uint workdim = 1;
			size_t local_work_size = 1;
			size_t global_work_size = parallel_tries;
			cl_ulong stride = parallel_tries;
			uint32_t argc = 0;
			cl_ulong2 index_range;
			cl_uint charset_type = (cl_uint)charset;
			float cur_progress = 0;

			index_range.s[0] = kdx;
			index_range.s[1] = ((kdx + charset_sz) < max_kernel_calls) ?
							(kdx + charset_sz) : max_kernel_calls;
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uchar8), &input);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uchar16), &digest);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_mem), &matches_mem);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_uint), &charset_type);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_ulong), &stride);
			rc |= clSetKernelArg(kernel, argc++, sizeof(cl_ulong2),
					&index_range);
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
				wc_util_timeofday(&tv2);
				WC_INFO("Found match in %luth kernel call: ",
						(unsigned long)kdx);
				for (l = 0; l < 8; ++l)
					WC_NULL("%c", match.s[l]);
				WC_NULL("\n");
				WC_INFO("Time taken for finding match: %lfs\n",
						WC_TIME_TAKEN(tv1, tv2));
				break;
			}
			cur_progress = (float)((kdx * 100.0) / max_kernel_calls);
			if ((cur_progress - progress) >= 1.0) {
				progress = cur_progress;
				if (ttinterval < 0.0) {
					wc_util_timeofday(&tv2);
					ttinterval = WC_TIME_TAKEN(tv1, tv2);
				}
				WC_INFO("Progress: %.02f%% Estimated Remaining Time: %lfs\n",
						progress, ttinterval * (100.0 - progress));
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
	char *buildopts = NULL;

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

	// we create the build options for nchars
	buildopts = wc_md5_create_buildopts(args.nchars);
	rc = wc_runtime_program_load(wc, (const char *)code, codelen, buildopts);
	if (rc < 0)
		WC_ERROR("Unable to compile the source code from %s\n",
				args.cl_filename ? args.cl_filename : WC_MD5_CL);

	rc = wc_md5_checker(wc, args.md5sum, args.prefix, args.charset,
			args.nchars);
	if (rc < 0)
		WC_ERROR("Unable to verify MD5 sums.\n");
	wc_runtime_destroy(wc);
	if (alloced)
		WC_FREE(code);
	WC_FREE(buildopts);
	wc_arguments_cleanup(&args);
	return rc;
}
