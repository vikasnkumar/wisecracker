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

typedef struct {
	char *cl_filename;
	uint32_t max_devices;
	wc_devtype_t device_type;
	wc_util_charset_t charset;
	uint8_t nchars; // a single byte can have values 0-255
	char *md5sum;
	char *prefix;
	struct crackmd5_per_device {
		cl_kernel kernel; // kernel
		cl_mem mem; // memory buffer
		cl_uchar16 match; // buffer to store output
		uint8_t nchars; // max value is 16
		cl_uint stride_argc;
		cl_ulong stride;
		size_t work_offset;
		size_t work_size;
	} *devices;
	uint32_t num_devices;
	uint64_t kernelcounter;
	// progress printing
	struct timeval tv1;
	struct timeval tv2;
	double prev_progress;
	double ttinterval;
	// store the result in this
	uint8_t found;
	cl_uchar16 match;
} crackmd5_user_t;

typedef struct {
	cl_uchar16 input;
	cl_uchar16 digest;
	cl_uint charset; // an integer copy of the charset
	uint8_t nchars;
} crackmd5_global_t;

typedef struct {
	cl_uchar16 match;
	uint64_t kernelcounter;
	int system_id;
} crackmd5_results_t;

int crackmd5_user_usage(const char *app)
{
	printf("\nUsage: %s [OPTIONS]\n", app);
	printf("\nOPTIONS are as follows:\n");
	printf("\n\t-h\t\tThis help message\n");
	printf("\n\t-v <value>\tLog level:\n"
			"\t\t\t0 - ERROR\n"
			"\t\t\t1 - WARN\n"
			"\t\t\t2 - INFO\n"
			"\t\t\t3 - DEBUG (Default)\n");
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

void crackmd5_user_init(crackmd5_user_t *user)
{
	if (!user)
		return;
	memset(user, 0, sizeof(crackmd5_user_t));
	user->cl_filename = NULL;
	user->max_devices = 0;
	user->device_type = WC_DEVTYPE_ANY;
	user->charset = WC_UTIL_CHARSET_ALNUM;
	user->nchars = 8;
	user->md5sum = NULL;
	user->prefix = NULL;
}

int crackmd5_user_parse(int argc, char **argv, crackmd5_user_t *user)
{
	int opt = -1;
	int rc = 0;
	const char *appname = NULL;
	int loglevel = WC_LOGLEVEL_DEBUG;
	if (!argv || !user)
		return -1;
	appname = WC_BASENAME(argv[0]);
	while ((opt = getopt(argc, argv, "hgcm:f:M:p:C:N:v:")) != -1) {
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
		case 'M':
			/* each byte is represented as 2 characters */
			if (strlen(optarg) == (2 * MD5_DIGEST_LENGTH)) {
				user->md5sum = wc_util_strdup(optarg);
				if (!user->md5sum) {
					WC_ERROR_OUTOFMEMORY(2 * MD5_DIGEST_LENGTH);
					rc = -1;
				}
			} else {
				WC_ERROR("Ignoring invalid MD5 sum: %s\n", optarg);
			}
			break;
		case 'p':
			user->prefix = wc_util_strdup(optarg);
			if (!user->prefix) {
				WC_ERROR_OUTOFMEMORY(strlen(optarg));
				rc = -1;
			}
			break;
		case 'C':
			user->charset = wc_util_charset_fromstring(optarg);
			break;
		case 'N':
			user->nchars = (uint8_t)strtol(optarg, NULL, 10);
			if (user->nchars < 1) {
				WC_ERROR("Invalid no. of characters given: %s.\n", optarg);
				rc = -1;
			} else if (user->nchars > 8) {
				WC_ERROR("%s does not support more than 8 characters.\n",
						appname);
				rc = -1;
			}
			break;
		case 'v':
			loglevel = (int)strtol(optarg, NULL, 10);
			if (loglevel > WC_LOGLEVEL_DEBUG)
				loglevel = WC_LOGLEVEL_DEBUG;
			else if (loglevel < WC_LOGLEVEL_ERROR)
				loglevel = WC_LOGLEVEL_ERROR;
			WC_SET_LOG_LEVEL(loglevel);
			break;
		case 'h':
		default:
			crackmd5_user_usage(appname);
			break;
		}
	}
	if (!user->md5sum) {
		WC_NULL("\n");
		WC_ERROR("You need to provide an MD5 sum to crack.\n");
		crackmd5_user_usage(appname);
		rc = -1;
	}
	return rc;
}

void crackmd5_user_dump(const crackmd5_user_t *user)
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
		WC_INFO("No. of chars: %u\n", user->nchars);
		WC_INFO("Charset: %s\n", wc_util_charset_tostring(user->charset));
		if (user->md5sum)
			WC_INFO("Will try to crack MD5 sum: %s\n", user->md5sum);
		if (user->prefix)
			WC_INFO("Will use prefix: %s\n", user->prefix);
	}
}

void crackmd5_user_cleanup(crackmd5_user_t *user)
{
	if (user) {
		WC_FREE(user->cl_filename);
		WC_FREE(user->md5sum);
		WC_FREE(user->prefix);
		WC_FREE(user->devices);
	}
}

uint64_t crackmd5_possibilities(wc_util_charset_t chs, uint8_t nchars)
{
	uint64_t result = 1;
	uint64_t chsz = wc_util_charset_size(chs);
	// calculate chsz ^ nchars here
	while (nchars) {
		if (nchars & 1)
			result *= chsz;
		nchars >>= 1;
		chsz *= chsz;
	}
	return result;
}

char *crackmd5_get_buildopts(const wc_exec_t *wc, void *user)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	if (!user)
		return NULL;
	if (cuser->nchars >= 1 && cuser->nchars <= 8) {
		char *buildopts = WC_MALLOC(256);
		if (buildopts) {
			int nc = (int)cuser->nchars;
			snprintf(buildopts, 256, "-DWC_MD5_CHECK_SIZE=%d", nc);
			return buildopts;
		} else {
			WC_ERROR_OUTOFMEMORY(256);
		}
	}
	return NULL;
}

void crackmd5_on_compile(const wc_exec_t *wc, void *user, uint8_t success)
{
	if (success) {
		WC_DEBUG("Code has been compiled successfully\n");
	} else {
		WC_DEBUG("Code failed to compile\n");
	}
}

char *crackmd5_get_code(const wc_exec_t *wc, void *user, size_t *codelen)
{
	unsigned char *code = NULL;
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	size_t clen = 0;
	if (cuser && cuser->cl_filename) {
		int rc = wc_util_glob_file(cuser->cl_filename, &code, &clen);
		if (rc < 0 || !code || clen < 1) {
			WC_ERROR("Unable to load code from %s\n", cuser->cl_filename);
			return NULL;
		}
		WC_INFO("Using custom code from %s\n", cuser->cl_filename);
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

uint64_t crackmd5_get_num_tasks(const wc_exec_t *wc, void *user)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	size_t pfxlen = 0;
	uint8_t zchars = 0;
	uint64_t max_possibilities = 0;
	if (!cuser)
		return 0;
	if (cuser->prefix)
		pfxlen = strlen(cuser->prefix);
	if (pfxlen >= cuser->nchars) {
		WC_WARN("Input string is already complete. Max length accepted is %d\n",
				(int)cuser->nchars);
		return 0;
	}
	zchars = cuser->nchars - (uint8_t)pfxlen;
	max_possibilities = crackmd5_possibilities(cuser->charset, zchars);
	if (max_possibilities == 0) {
		WC_WARN("Max possibilities was calculated to be 0 for %s of %d chars\n",
				wc_util_charset_tostring(cuser->charset), (int)zchars);
		return 0;
	}
	WC_INFO("Max possibilities: %"PRIu64"\n", max_possibilities);
	return max_possibilities;
}

wc_err_t crackmd5_on_start(const wc_exec_t *wc, void *user)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	if (cuser) {
		const size_t wcpdsz = sizeof(struct crackmd5_per_device);
		cuser->num_devices = wc_executor_num_devices(wc);
		if (cuser->num_devices == 0) {
			WC_DEBUG("No devices found on the system\n");
			return WC_EXE_ERR_OPENCL;
		}
		cuser->devices = WC_MALLOC(cuser->num_devices * wcpdsz);
		if (!cuser->devices) {
			cuser->num_devices = 0;
			WC_ERROR_OUTOFMEMORY(cuser->num_devices * wcpdsz);
			return WC_EXE_ERR_OUTOFMEMORY;
		}
		memset(cuser->devices, 0, cuser->num_devices * wcpdsz);
		cuser->kernelcounter = 0;
		wc_util_timeofday(&cuser->tv1);
		cuser->prev_progress = 0.0;
		cuser->ttinterval = -1.0;
	} else {
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	return WC_EXE_OK;
}

wc_err_t crackmd5_on_finish(const wc_exec_t *wc, void *user)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	if (cuser) {
		WC_FREE(cuser->devices);
		cuser->num_devices = 0;
		WC_DEBUG("Number of kernels executed: %"PRIu64"\n",
				cuser->kernelcounter);
	} else {
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	return WC_EXE_OK;
}

wc_err_t crackmd5_get_global_data(const wc_exec_t *wc, void *user,
								wc_data_t *out)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	crackmd5_global_t *gd = WC_MALLOC(sizeof(*gd));
	size_t pfxlen = 0;
	size_t idx;
	if (!user || !out)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!gd) {
		WC_ERROR_OUTOFMEMORY(sizeof(*gd));
		return WC_EXE_ERR_OUTOFMEMORY;
	}
	pfxlen = (cuser->prefix) ? strlen(cuser->prefix) : 0;
	memset(gd, 0, sizeof(*gd));
	// copy the initial input
	for (idx = 0; idx < pfxlen; ++idx)
		gd->input.s[idx] = (cl_uchar)cuser->prefix[idx];
	// convert md5sum text to a digest
	for (idx = 0; idx < 2 * MD5_DIGEST_LENGTH; idx += 2)
		gd->digest.s[idx >> 1] = (wc_md5_decoder[(int)cuser->md5sum[idx]] << 4) |
							wc_md5_decoder[(int)cuser->md5sum[idx + 1]];

	gd->charset = (cl_uint)cuser->charset;
	gd->nchars = cuser->nchars;
	out->ptr = gd;
	out->len = (uint32_t)sizeof(*gd);
	return WC_EXE_OK;
}

void crackmd5_free_global_data(const wc_exec_t *wc, void *user,
								wc_data_t *gdata)
{
	if (gdata) {
		WC_FREE(gdata->ptr);
		gdata->len = 0;
	}
}

wc_err_t crackmd5_on_recv_global(const wc_exec_t *wc, void *user,
				const wc_data_t *gdata)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	if (gdata && gdata->ptr) {
		int i;
		const crackmd5_global_t *gd = NULL;
		gd = (const crackmd5_global_t *)gdata->ptr;
		WC_INFO("Global prefix: ");
		for (i = 0; i < 16; ++i) {
			if (gd->input.s[i])
				WC_NULL("%c", gd->input.s[i]);
		}
		WC_NULL("\n");
		WC_INFO("Digest: ");
		for (i = 0; i < 16; ++i) {
			WC_NULL("%x", gd->digest.s[i]);
		}
		WC_NULL("\n");
		WC_INFO("Charset: %s\n", wc_util_charset_tostring(gd->charset));
		WC_INFO("No. of chars: %d\n", gd->nchars);
		cuser->nchars = gd->nchars;
		cuser->charset = gd->charset;
	}
	return WC_EXE_OK;
}

uint32_t crackmd5_get_multiplier(const wc_exec_t *wc, void *user)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	if (cuser)
		return (uint32_t)wc_util_charset_size(cuser->charset) * 32;
	return 1;
}

void crackmd5_progress(float percent, void *user)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	if (cuser) {
		if ((percent - cuser->prev_progress) > 0.5) {
			cuser->prev_progress = percent;
			if (cuser->ttinterval < 0.0) {
				wc_util_timeofday(&cuser->tv2);
				cuser->ttinterval = WC_TIME_TAKEN(cuser->tv1, cuser->tv2);
			}
			WC_INFO("Progress: %.02f%% Estimated Remaining Time: %lf seconds\n",
					percent, cuser->ttinterval * (100.0 - percent));
		}
	}
}

wc_err_t crackmd5_on_device_start(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, const wc_data_t *gdata)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	cl_int rc = CL_SUCCESS;
	const crackmd5_global_t *gd = NULL;
	if (!wc || !dev || !cuser || !gdata || !gdata->ptr)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!cuser->devices || devindex >= cuser->num_devices ||
			gdata->len < sizeof(*gd))
		return WC_EXE_ERR_BAD_STATE;
	gd = (const crackmd5_global_t *)gdata->ptr;

	do {
		cl_uint argc = 0;
		struct crackmd5_per_device *cpd = &cuser->devices[devindex];

		cpd->nchars = gd->nchars;
		// create the kernel and memory objects per device
		cpd->kernel = clCreateKernel(dev->program, wc_md5_cl_kernel, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
		cpd->mem = clCreateBuffer(dev->context, CL_MEM_READ_WRITE,
									sizeof(cl_uchar16), NULL, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
		// now we assign the arguments to each kernel
		argc = 0;
		rc |= clSetKernelArg(cpd->kernel, argc++, sizeof(cl_uchar16),
				&gd->input);
		rc |= clSetKernelArg(cpd->kernel, argc++, sizeof(cl_uchar16),
				&gd->digest);
		rc |= clSetKernelArg(cpd->kernel, argc++, sizeof(cl_mem),
				&cpd->mem);
		rc |= clSetKernelArg(cpd->kernel, argc++, sizeof(cl_uint),
				&gd->charset);
		// store the stride argument
		cpd->stride_argc = argc;
		cpd->stride = 0;
		rc |= clSetKernelArg(cpd->kernel, cpd->stride_argc, sizeof(cl_ulong),
				&cpd->stride);
		WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
	} while (0);
	return (rc == CL_SUCCESS) ? WC_EXE_OK : WC_EXE_ERR_OPENCL;
}

wc_err_t crackmd5_on_device_range_exec(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, const wc_data_t *gdata,
		uint64_t start, uint64_t end, cl_event *outevent)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	cl_int rc = CL_SUCCESS;
	const crackmd5_global_t *gd = NULL;
	if (!wc || !dev || !cuser || !gdata || !gdata->ptr)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!cuser->devices || devindex >= cuser->num_devices ||
			gdata->len < sizeof(*gd))
		return WC_EXE_ERR_BAD_STATE;
	if (start > end)
		return WC_EXE_ERR_INVALID_PARAMETER;

	gd = (const crackmd5_global_t *)gdata->ptr;
	do {
		const cl_uint workdim = 1;
		uint64_t offset_limit = 0;
		struct crackmd5_per_device *cpd = &cuser->devices[devindex];

		cpd->work_offset = start;
		cpd->work_size = end - start;
		if (dev->address_bits == sizeof(cl_uint) * CL_CHAR_BIT) {
			offset_limit = CL_UINT_MAX;
		} else if (dev->address_bits == sizeof(cl_ulong) * CL_CHAR_BIT) {
			offset_limit = CL_ULONG_MAX;
		} else {
			// play it safe
			offset_limit = CL_UINT_MAX;
		}
		memset(&(cpd->match), 0, sizeof(cl_uchar16));
		// check for global_work_offset_limit here and adjust stride
		if ((cpd->work_offset + cpd->work_size) >= offset_limit) {
//			WC_DEBUG("Work offset: %"PRIu64" size: %"PRIu64" for device[%u]\n",
//					(uint64_t)cpd->work_offset, (uint64_t)cpd->work_size, devindex);
			// this is more efficient rather than using the offset
			cpd->stride = cpd->work_offset;
			cpd->work_offset = 0;
			rc |= clSetKernelArg(cpd->kernel, cpd->stride_argc,
					sizeof(cl_ulong), &cpd->stride);
			WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
//			WC_DEBUG("Global work offset reset to %"PRIu64". Stride: %"PRIu64"\n",
//					(uint64_t)cpd->work_offset, cpd->stride);
//			WC_DEBUG("Reset for kernel number: %"PRIu64"\n", cuser->kernelcounter);
		}
		// enqueue the mem-write for the device
		rc = clEnqueueWriteBuffer(dev->cmdq, cpd->mem, CL_FALSE,
				0, sizeof(cl_uchar16), &cpd->match, 0, NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
		// enqueue the kernel for the device
		rc = clEnqueueNDRangeKernel(dev->cmdq, cpd->kernel, workdim,
				&(cpd->work_offset), &(cpd->work_size), NULL,
				0, NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueNDRangeKernel, rc);
		// enqueue the mem-read for the device
		rc = clEnqueueReadBuffer(dev->cmdq, cpd->mem, CL_FALSE,
				0, sizeof(cl_uchar16), &cpd->match, 0, NULL,
				outevent);
		WC_ERROR_OPENCL_BREAK(clEnqueueReadBuffer, rc);
		cuser->kernelcounter++;
	} while (0);
	return (rc == CL_SUCCESS) ? WC_EXE_OK : WC_EXE_ERR_OPENCL;
}

wc_err_t crackmd5_on_device_range_done(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, const wc_data_t *gdata,
		uint64_t start, uint64_t end, wc_data_t *results)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	struct crackmd5_per_device *cpd = NULL;
	if (!wc || !dev || !cuser)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!cuser->devices || devindex >= cuser->num_devices)
		return WC_EXE_ERR_BAD_STATE;
	// nullify result for those that do not match
	if (results) {
		results->ptr = NULL;
		results->len = 0;
	}
	// check for matches
	cpd = &cuser->devices[devindex];
	if (cpd->match.s[0] != 0) {
		int8_t l = 0;
		crackmd5_results_t *res = NULL;
		WC_INFO("Found match in %"PRIu64"th kernel call: ", cuser->kernelcounter);
		for (l = 0; l < cpd->nchars; ++l)
			WC_NULL("%c", cpd->match.s[l]);
		WC_NULL("\n");
//		cuser->found = 1;
//		memcpy(&cuser->match, &cpd->match, sizeof(cpd->match));

		res = WC_MALLOC(sizeof(*res));
		if (res) {
			memset(res, 0, sizeof(*res));
			memcpy(&res->match, &cpd->match, sizeof(cpd->match));
			res->kernelcounter = cuser->kernelcounter;
			res->system_id = wc_executor_system_id(wc);
			if (results) {
				results->ptr = res;
				results->len = sizeof(*res);
			}
		} else {
			WC_ERROR_OUTOFMEMORY(sizeof(*res));
			return WC_EXE_ERR_OUTOFMEMORY;
		}
		// we want to signal end of run over here across systems
		return WC_EXE_STOP;
	}
	return WC_EXE_OK;
}

wc_err_t crackmd5_on_device_finish(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, const wc_data_t *gdata)
{
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	cl_int rc = CL_SUCCESS;
	struct crackmd5_per_device *cpd = NULL;
	if (!wc || !dev || !cuser)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!cuser->devices || devindex >= cuser->num_devices)
		return WC_EXE_ERR_BAD_STATE;

	// free the memory and other objects
	cpd = &cuser->devices[devindex];
	if (cpd->kernel) {
		rc = clReleaseKernel(cpd->kernel);
		cpd->kernel = (cl_kernel)0;
		if (rc != CL_SUCCESS)
			WC_ERROR_OPENCL(clReleaseMemObject, rc);
	}
	if (cpd->mem) {
		rc = clReleaseMemObject(cpd->mem);
		cpd->mem = (cl_mem)0;
		if (rc != CL_SUCCESS)
			WC_ERROR_OPENCL(clReleaseMemObject, rc);
	}
	return (rc == CL_SUCCESS) ? WC_EXE_OK : WC_EXE_ERR_OPENCL;
}

wc_err_t crackmd5_on_recv_results(const wc_exec_t *wc, void *user,
					uint64_t start, uint64_t end, wc_err_t slverr,
					const wc_data_t *results)
{
	wc_err_t rc;
	crackmd5_user_t *cuser = (crackmd5_user_t *)user;
	if (!wc || !user || !results || (start > end))
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (slverr != WC_EXE_OK && slverr != WC_EXE_STOP) {
		WC_WARN("For task range (%"PRIu64", %"PRIu64") error: %d\n",
				start, end, slverr);
		rc = WC_EXE_OK;
	} else if (slverr == WC_EXE_STOP) {
		WC_WARN("For task range (%"PRIu64", %"PRIu64") stop called on slave\n",
				start, end);
		rc = WC_EXE_STOP;
	} else {
		rc = WC_EXE_OK;
	}
	if (results && results->ptr &&
		results->len == sizeof(crackmd5_results_t)) {
		crackmd5_results_t *res = (crackmd5_results_t *)results->ptr;
		cuser->found = 1;
		memcpy(&cuser->match, &res->match, sizeof(res->match));
		WC_INFO("Found match in %"PRIu64"th kernel call on system %d\n",
				res->kernelcounter, res->system_id);
	}
	return rc;
}

int main(int argc, char **argv)
{
	wc_err_t err = WC_EXE_OK;
	wc_exec_t *wc = NULL;
	crackmd5_user_t user;
	wc_exec_callbacks_t callbacks;

	// print license
	WC_NULL("%s\n", wc_util_license());

	wc = wc_executor_init(&argc, &argv);
	assert(wc != NULL);
	do {
		struct timeval tv1, tv2;
		wc_util_timeofday(&tv1);
		crackmd5_user_init(&user);
		if (crackmd5_user_parse(argc, argv, &user) < 0) {
			WC_ERROR("Unable to parse arguments.\n");
			return -1;
		}
		crackmd5_user_dump(&user);
		// set up the callbacks for distribution
		memset(&callbacks, 0, sizeof(callbacks));
		callbacks.user = &user;
		callbacks.max_devices = user.max_devices;
		callbacks.device_type = user.device_type;
		callbacks.on_start = crackmd5_on_start;
		callbacks.on_finish = crackmd5_on_finish;
		callbacks.get_code = crackmd5_get_code;
		callbacks.get_build_options = crackmd5_get_buildopts;
		callbacks.get_num_tasks = crackmd5_get_num_tasks;
		callbacks.get_task_range_multiplier = crackmd5_get_multiplier;
		callbacks.on_code_compile = crackmd5_on_compile;
		callbacks.get_global_data = crackmd5_get_global_data;
		callbacks.on_receive_global_data = crackmd5_on_recv_global;
		callbacks.on_device_start = crackmd5_on_device_start;
		callbacks.on_device_finish = crackmd5_on_device_finish;
		callbacks.on_device_range_exec = crackmd5_on_device_range_exec;
		callbacks.on_device_range_done = crackmd5_on_device_range_done;
		callbacks.on_receive_range_results = crackmd5_on_recv_results;
		callbacks.free_global_data = crackmd5_free_global_data;
		callbacks.progress = crackmd5_progress;

		err = wc_executor_setup(wc, &callbacks);
		assert(err == WC_EXE_OK);
		if (err != WC_EXE_OK) {
			WC_ERROR("Error setting up callbacks: %d\n", err);
			break;
		}
		// print information of the executor object on screen
		wc_executor_dump(wc);
		err = wc_executor_run(wc);
		if (err != WC_EXE_OK) {
			WC_ERROR("Unable to crack MD5 sum. Error: %d\n", err);
			break;
		} else {
			// if i am not the root system, break out
			if (wc_executor_system_id(wc) != 0)
				break;
			if (!user.found) {
				WC_INFO("Unable to find a match\n");
			} else {
				uint8_t l;
				WC_INFO("Found match: ");
				for (l = 0; l < user.nchars; ++l)
					WC_NULL("%c", user.match.s[l]);
				WC_NULL("\n");
			}
			wc_util_timeofday(&tv2);
			WC_INFO("Time taken for cracking: %lf seconds\n",
					WC_TIME_TAKEN(tv1, tv2));
		}
	} while (0);
	wc_executor_destroy(wc);
	crackmd5_user_cleanup(&user);
	return (int)err;
}
