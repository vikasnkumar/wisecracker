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
const char *wc_md5_cl_kernel = "wc_md5sum_check";

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
	printf("\n\t-m <value>\tMaximum devices to use, 0 (default) for all.\n");
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
	args->max_devices = 0;
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
			args->charset = wc_util_charset_fromstring(optarg);
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
		if (args->max_devices)
			WC_INFO("Max Devices to use: %u\n", args->max_devices);
		else
			WC_INFO("Max Devices to use: all available\n");
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
			snprintf(buildopts, 256, "-DWC_MD5_CHECK_SIZE=%d", (int)nchars);
			return buildopts;
		} else {
			WC_ERROR_OUTOFMEMORY(256);
		}
	}
	return NULL;
}

int wc_md5_checker(wc_runtime_t *wc, const char *md5sum, const char *prefix,
		wc_util_charset_t charset, const uint8_t nchars)
{
	cl_int rc = CL_SUCCESS;
	uint32_t idx;
	cl_ulong max_possibilities = 0;
	cl_uchar16 input;
	cl_uchar16 digest;
	size_t pfxlen = 0;
	uint8_t zchars = 0;
	cl_ulong total_parallel_tries = 0;
	cl_kernel *kernels = NULL; // a kernel per device
	cl_mem *match_mems = NULL; // a memory buffer per device
	cl_uchar16 *matches = NULL; // a buffer to store the output per device
	cl_ulong *parallel_tries = NULL; // parallel_tries per device
	cl_event *dev_events = NULL; // event per device for now

	cl_ulong charset_sz = wc_util_charset_size(charset);
	if (!md5sum || !wc_runtime_is_usable(wc) || (nchars < 1) || (nchars >= 16))
		return -1;
	if (strlen(md5sum) != (2 * MD5_DIGEST_LENGTH))
		return -1;
	pfxlen = prefix ? strlen(prefix) : 0;
	if (pfxlen >= nchars) {
		WC_WARN("Input string is already complete. Max length accepted is %d\n",
				(int)nchars);
		return -1;
	}
	zchars = nchars - (uint8_t)pfxlen;
	max_possibilities = wc_md5_possibilities(charset, zchars);
	if (max_possibilities == 0) {
		WC_WARN("Max possibilities was calculated to be 0 for %s of %d chars\n",
				wc_util_charset_tostring(charset), (int)zchars);
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
	// for each device, create a kernel object and a memory buffer object
	// this is necessary since each device has its own command-queue
	do {
		cl_ulong max_kernel_calls = 0;
		cl_uint charset_type = (cl_uint)charset;
		size_t global_work_offset[1] = { 0 };
		size_t global_work_size[1] = { 0 };
		cl_ulong kdx;
		struct timeval tv1, tv2;
		float progress = 0.0;
		double ttinterval = -1.0;
		cl_int found = -1; // index of matches which has the result

		kernels = WC_MALLOC(sizeof(cl_kernel) * wc->device_max);
		if (!kernels) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_kernel) * wc->device_max);
			rc = -1;
			break;
		}
		memset(kernels, 0, sizeof(cl_kernel) * wc->device_max);
		match_mems = WC_MALLOC(sizeof(cl_mem) * wc->device_max);
		if (!match_mems) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_mem) * wc->device_max);
			rc = -1;
			break;
		}
		memset(match_mems, 0, sizeof(cl_mem) * wc->device_max);
		parallel_tries = WC_MALLOC(sizeof(cl_ulong) * wc->device_max);
		if (!parallel_tries) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_ulong) * wc->device_max);
			rc = -1;
			break;
		}
		memset(parallel_tries, 0, sizeof(cl_ulong) * wc->device_max);
		matches = WC_MALLOC(sizeof(cl_uchar16) * wc->device_max);
		if (!matches) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_uchar16) * wc->device_max);
			rc = -1;
			break;
		}
		memset(matches, 0, sizeof(cl_uchar16) * wc->device_max);
		dev_events = WC_MALLOC(sizeof(cl_event) * wc->device_max);
		if (!dev_events) {
			WC_ERROR_OUTOFMEMORY(sizeof(cl_event) * wc->device_max);
			rc = -1;
			break;
		}
		memset(dev_events, 0, sizeof(cl_event) * wc->device_max);
		for (idx = 0; idx < wc->device_max; ++idx) {
			wc_device_t *dev = &wc->devices[idx];
			wc_platform_t *plat = NULL;
			cl_ulong localmem_per_kernel = 0;
			cl_uint argc = 0;
			if (dev->pl_index >= wc->platform_max) {
				WC_ERROR("Invalid device platform index.\n");
				rc = -1;
				break;
			}
			plat = &wc->platforms[dev->pl_index];
			// create the kernel and memory objects per device
			kernels[idx] = (cl_kernel)0;
			match_mems[idx] = (cl_mem)0;
			kernels[idx] = clCreateKernel(plat->program, wc_md5_cl_kernel, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
			match_mems[idx] = clCreateBuffer(plat->context, CL_MEM_READ_WRITE,
					sizeof(cl_uchar16), NULL, &rc);
			WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
			// max tries allowed based on local memory availability
			clGetKernelWorkGroupInfo(kernels[idx], dev->id,
					CL_KERNEL_LOCAL_MEM_SIZE, sizeof(cl_ulong),
					&localmem_per_kernel, NULL);
			WC_ERROR_OPENCL_BREAK(clGetKernelWorkGroupInfo, rc);
			WC_DEBUG("local mem per kernel: %lu\n", localmem_per_kernel);
			if (localmem_per_kernel < 32)
				localmem_per_kernel = 32;
			parallel_tries[idx] = dev->localmem_sz / localmem_per_kernel;
			// scale the tries to number of compute units times the charset
			// size.
			parallel_tries[idx] *= (dev->compute_units * charset_sz);
			WC_DEBUG("Parallel tries for device[%u] is %lu\n", idx,
					parallel_tries[idx]);
			total_parallel_tries += parallel_tries[idx];
			// now we assign the arguments to each kernel
			argc = 0;
			rc |= clSetKernelArg(kernels[idx], argc++, sizeof(cl_uchar16),
					&input);
			rc |= clSetKernelArg(kernels[idx], argc++, sizeof(cl_uchar16),
					&digest);
			rc |= clSetKernelArg(kernels[idx], argc++, sizeof(cl_mem),
					&match_mems[idx]);
			rc |= clSetKernelArg(kernels[idx], argc++, sizeof(cl_uint),
					&charset_type);
			WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
		}
		if (rc < 0)
			break;
		if (max_possibilities <= total_parallel_tries) {
			max_kernel_calls = 1;
			total_parallel_tries = max_possibilities;
		} else {
			// find the ceiling maximum number of kernel calls needed
			max_kernel_calls = (max_possibilities / total_parallel_tries) +
				((max_possibilities % total_parallel_tries) ? 1 : 0);
		}
		WC_INFO("Maximum Kernel calls: %lu Parallel Tries Per Call: %lu\n",
				(unsigned long)max_kernel_calls,
				total_parallel_tries);
		global_work_offset[0] = 0;
		wc_util_timeofday(&tv1);
		found = -1;
		progress = 0.0;
		for (kdx = 0; kdx < max_kernel_calls; ++kdx) {
			float cur_progress = 0.0;
			cl_uint event_count = 0;
			// zero out the matches buffer
			memset(matches, 0, sizeof(cl_uchar16) * wc->device_max);
			memset(dev_events, 0, sizeof(cl_event) * wc->device_max);
			// enqueue all the required calls for every device
			for (idx = 0; idx < wc->device_max; ++idx) {
				const cl_uint workdim = 1;
				wc_device_t *dev = &wc->devices[idx];
				global_work_size[0] = parallel_tries[idx];
//				WC_DEBUG("Work offset: %lu size: %lu for device[%u]\n",
//						global_work_offset[0], global_work_size[0], idx);
				// enqueue the mem-write for the device
				rc = clEnqueueWriteBuffer(dev->cmdq, match_mems[idx], CL_FALSE,
						0, sizeof(cl_uchar16), &matches[idx], 0, NULL, NULL);
				WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
				// enqueue the kernel for the device
				rc = clEnqueueNDRangeKernel(dev->cmdq, kernels[idx], workdim,
						global_work_offset, global_work_size, NULL,
						0, NULL, NULL);
				WC_ERROR_OPENCL_BREAK(clEnqueueNDRangeKernel, rc);
				// enqueue the mem-read for the device
				rc = clEnqueueReadBuffer(dev->cmdq, match_mems[idx], CL_FALSE,
						0, sizeof(cl_uchar16), &matches[idx], 0, NULL,
						&dev_events[event_count++]);
				WC_ERROR_OPENCL_BREAK(clEnqueueReadBuffer, rc);
				rc = clFlush(dev->cmdq);
				WC_ERROR_OPENCL_BREAK(clFlush, rc);
				global_work_offset[0] += global_work_size[0];
				if (global_work_offset[0] >= max_possibilities)
					break;
			}
			if (rc < 0) {
				WC_ERROR("Errored out in the %luth kernel\n", kdx);
				break;
			}
			// wait for all the devices to complete work FIXME: inefficient
			rc = clWaitForEvents(event_count, dev_events);
			WC_ERROR_OPENCL_BREAK(clWaitForEvents, rc);
			for (idx = 0; idx < event_count; ++idx) {
				rc |= clReleaseEvent(dev_events[idx]);
				dev_events[idx] = (cl_event)0;
			}
			// ok now check for matches
			for (idx = 0; idx < wc->device_max; ++idx) {
				if (matches[idx].s[0] != 0) {
					int8_t l = 0;
					wc_util_timeofday(&tv2);
					WC_INFO("Found match in %luth kernel call: ",
							(unsigned long)kdx);
					for (l = 0; l < nchars; ++l)
						WC_NULL("%c", matches[idx].s[l]);
					WC_NULL("\n");
					WC_INFO("Time taken for finding match: %lfs\n",
							WC_TIME_TAKEN(tv1, tv2));
					found = idx;
					break;
				}
			}
			if (found >= 0) {
				rc = CL_SUCCESS;
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
		if (rc < 0)
			break;
		if (found < 0) {
			WC_INFO("Unable to find a match.\n");
		}
	} while (0);
	// free the memory and other objects
	for (idx = 0; idx < wc->device_max; ++idx) {
		if (kernels && kernels[idx]) {
			rc |= clReleaseKernel(kernels[idx]);
			kernels[idx] = (cl_kernel)0;
		}
		if (match_mems && match_mems[idx]) {
			rc |= clReleaseMemObject(match_mems[idx]);
			match_mems[idx] = (cl_mem)0;
		}
		if (dev_events && dev_events[idx]) {
			rc |= clReleaseEvent(dev_events[idx]);
			dev_events[idx] = (cl_event)0;
		}
	}
	WC_FREE(kernels);
	WC_FREE(match_mems);
	WC_FREE(parallel_tries);
	WC_FREE(matches);
	WC_FREE(dev_events);
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

	wc = wc_runtime_create(args.device_flag, args.max_devices, 0);
	assert(wc != NULL);
	wc_runtime_dump(wc);

	// we create the build options for nchars
	buildopts = wc_md5_create_buildopts(args.nchars);
	do {
		rc = wc_runtime_program_load(wc, (const char *)code, codelen,
				buildopts);
		if (rc < 0) {
			WC_ERROR("Unable to compile the source code from %s\n",
					args.cl_filename ? args.cl_filename : WC_MD5_CL);
			break;
		}
		rc = wc_md5_checker(wc, args.md5sum, args.prefix, args.charset,
							args.nchars);
		if (rc < 0) {
			WC_ERROR("Unable to verify MD5 sums.\n");
			break;
		}
	} while (0);
	wc_runtime_destroy(wc);
	if (alloced)
		WC_FREE(code);
	WC_FREE(buildopts);
	wc_arguments_cleanup(&args);
	return rc;
}
