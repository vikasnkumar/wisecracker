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

struct wc_user {
	char *cl_filename;
	uint32_t max_devices;
	wc_devtype_t device_type;
	wc_util_charset_t charset;
	uint8_t nchars; // a single byte can have values 0-255
	char *md5sum;
	char *prefix;
	struct wc_per_device {
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
};

struct wc_global_data {
	cl_uchar16 input;
	cl_uchar16 digest;
	cl_uint charset; // an integer copy of the charset
};

int wc_user_usage(const char *app)
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

int wc_user_parse(int argc, char **argv, struct wc_user *user)
{
	int opt = -1;
	int rc = 0;
	const char *appname = NULL;
	if (!argv || !user)
		return -1;
	user->cl_filename = NULL;
	user->max_devices = 0;
	user->device_type = WC_DEVTYPE_ANY;
	user->charset = WC_UTIL_CHARSET_ALNUM;
	user->nchars = 8;
	user->md5sum = NULL;
	user->prefix = NULL;
	appname = WC_BASENAME(argv[0]);
	while ((opt = getopt(argc, argv, "hgcm:f:M:p:C:N:")) != -1) {
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
		case 'h':
		default:
			wc_user_usage(appname);
			break;
		}
	}
	if (!user->md5sum) {
		WC_NULL("\n");
		WC_ERROR("You need to provide an MD5 sum to crack.\n");
		wc_user_usage(argv[0]);
		rc = -1;
	}
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
		WC_INFO("No. of chars: %u\n", user->nchars);
		WC_INFO("Charset: %s\n", wc_util_charset_tostring(user->charset));
		if (user->md5sum)
			WC_INFO("Will try to crack MD5 sum: %s\n", user->md5sum);
		if (user->prefix)
			WC_INFO("Will use prefix: %s\n", user->prefix);
	}
}

void wc_user_cleanup(struct wc_user *user)
{
	if (user) {
		WC_FREE(user->cl_filename);
		WC_FREE(user->md5sum);
		WC_FREE(user->prefix);
		WC_FREE(user->devices);
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
	struct wc_user *wcu = (struct wc_user *)user;
	if (!user)
		return NULL;
	if (wcu->nchars >= 1 && wcu->nchars <= 8) {
		char *buildopts = WC_MALLOC(256);
		if (buildopts) {
			int nc = (int)wcu->nchars;
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

uint64_t crackmd5_get_num_tasks(const wc_exec_t *wc, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	size_t pfxlen = 0;
	uint8_t zchars = 0;
	uint64_t max_possibilities = 0;
	if (!wcu)
		return 0;
	if (wcu->prefix)
		pfxlen = strlen(wcu->prefix);
	if (pfxlen >= wcu->nchars) {
		WC_WARN("Input string is already complete. Max length accepted is %d\n",
				(int)wcu->nchars);
		return 0;
	}
	zchars = wcu->nchars - (uint8_t)pfxlen;
	max_possibilities = crackmd5_possibilities(wcu->charset, zchars);
	if (max_possibilities == 0) {
		WC_WARN("Max possibilities was calculated to be 0 for %s of %d chars\n",
				wc_util_charset_tostring(wcu->charset), (int)zchars);
		return 0;
	}
	WC_INFO("Max possibilities: %lu\n", max_possibilities);
	return max_possibilities;
}

wc_err_t crackmd5_on_start(const wc_exec_t *wc, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	if (wcu) {
		const size_t wcpdsz = sizeof(struct wc_per_device);
		wcu->num_devices = wc_executor_num_devices(wc);
		if (wcu->num_devices == 0) {
			WC_DEBUG("No devices found on the system\n");
			return WC_EXE_ERR_OPENCL;
		}
		wcu->devices = WC_MALLOC(wcu->num_devices * wcpdsz);
		if (!wcu->devices) {
			wcu->num_devices = 0;
			WC_ERROR_OUTOFMEMORY(wcu->num_devices * wcpdsz);
			return WC_EXE_ERR_OUTOFMEMORY;
		}
		memset(wcu->devices, 0, wcu->num_devices * wcpdsz);
		wcu->kernelcounter = 0;
		wc_util_timeofday(&wcu->tv1);
		wcu->prev_progress = 0.0;
		wcu->ttinterval = -1.0;
	} else {
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	return WC_EXE_OK;
}

wc_err_t crackmd5_on_finish(const wc_exec_t *wc, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	if (wcu) {
		WC_FREE(wcu->devices);
		wcu->num_devices = 0;
	} else {
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	return WC_EXE_OK;
}

wc_err_t crackmd5_get_global_data(const wc_exec_t *wc, void *user,
								wc_data_t *out)
{
	struct wc_user *wcu = (struct wc_user *)user;
	struct wc_global_data *gd = WC_MALLOC(sizeof(*gd));
	size_t pfxlen = 0;
	size_t idx;
	if (!user || !out)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!gd) {
		WC_ERROR_OUTOFMEMORY(sizeof(*gd));
		return WC_EXE_ERR_OUTOFMEMORY;
	}
	pfxlen = (wcu->prefix) ? strlen(wcu->prefix) : 0;
	memset(gd, 0, sizeof(*gd));
	// copy the initial input
	for (idx = 0; idx < pfxlen; ++idx)
		gd->input.s[idx] = (cl_uchar)wcu->prefix[idx];
	// convert md5sum text to a digest
	for (idx = 0; idx < 2 * MD5_DIGEST_LENGTH; idx += 2)
		gd->digest.s[idx >> 1] = (wc_md5_decoder[(int)wcu->md5sum[idx]] << 4) |
							wc_md5_decoder[(int)wcu->md5sum[idx + 1]];

	gd->charset = (cl_uint)wcu->charset;
	out->ptr = gd;
	out->len = sizeof(*gd);
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

uint32_t crackmd5_get_multiplier(const wc_exec_t *wc, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	if (wcu)
		return (uint32_t)wc_util_charset_size(wcu->charset);
	return 1;
}

void crackmd5_progress(float percent, void *user)
{
	struct wc_user *wcu = (struct wc_user *)user;
	if (wcu) {
		if ((percent - wcu->prev_progress) > 0.5) {
			wcu->prev_progress = percent;
			if (wcu->ttinterval < 0.0) {
				wc_util_timeofday(&wcu->tv2);
				wcu->ttinterval = WC_TIME_TAKEN(wcu->tv1, wcu->tv2);
			}
			WC_INFO("Progress: %.02f%% Estimated Remaining Time: %lf seconds\n",
					percent, wcu->ttinterval * (100.0 - percent));
		}
	}
}

wc_err_t crackmd5_on_device_start(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, wc_data_t *gdata)
{
	struct wc_user *wcu = (struct wc_user *)user;
	cl_int rc = CL_SUCCESS;
	struct wc_global_data *gd = NULL;
	if (!wc || !dev || !wcu || !gdata || !gdata->ptr)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!wcu->devices || devindex >= wcu->num_devices ||
			gdata->len < sizeof(*gd))
		return WC_EXE_ERR_BAD_STATE;
	gd = (struct wc_global_data *)gdata->ptr;

	do {
		cl_uint argc = 0;
		struct wc_per_device *wcd = &wcu->devices[devindex];

		wcd->nchars = wcu->nchars;
		// create the kernel and memory objects per device
		wcd->kernel = clCreateKernel(dev->program, wc_md5_cl_kernel, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateKernel, rc);
		wcd->mem = clCreateBuffer(dev->context, CL_MEM_READ_WRITE,
									sizeof(cl_uchar16), NULL, &rc);
		WC_ERROR_OPENCL_BREAK(clCreateBuffer, rc);
		// now we assign the arguments to each kernel
		argc = 0;
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_uchar16),
				&gd->input);
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_uchar16),
				&gd->digest);
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_mem),
				&wcd->mem);
		rc |= clSetKernelArg(wcd->kernel, argc++, sizeof(cl_uint),
				&gd->charset);
		// store the stride argument
		wcd->stride_argc = argc;
		wcd->stride = 0;
		rc |= clSetKernelArg(wcd->kernel, wcd->stride_argc, sizeof(cl_ulong),
				&wcd->stride);
		WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
	} while (0);
	return (rc == CL_SUCCESS) ? WC_EXE_OK : WC_EXE_ERR_OPENCL;
}

wc_err_t crackmd5_on_device_range_exec(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, wc_data_t *gdata,
		uint64_t start, uint64_t end, cl_event *outevent)
{
	struct wc_user *wcu = (struct wc_user *)user;
	cl_int rc = CL_SUCCESS;
	struct wc_global_data *gd = NULL;
	if (!wc || !dev || !wcu || !gdata || !gdata->ptr)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!wcu->devices || devindex >= wcu->num_devices ||
			gdata->len < sizeof(*gd))
		return WC_EXE_ERR_BAD_STATE;
	gd = (struct wc_global_data *)gdata->ptr;
	do {
		const cl_uint workdim = 1;
		uint64_t offset_limit = 0;
		struct wc_per_device *wcd = &wcu->devices[devindex];

		wcd->work_offset = start;
		wcd->work_size = end - start;
		if (dev->address_bits == sizeof(cl_uint) * CL_CHAR_BIT) {
			offset_limit = CL_UINT_MAX;
		} else if (dev->address_bits == sizeof(cl_ulong) * CL_CHAR_BIT) {
			offset_limit = CL_ULONG_MAX;
		} else {
			// play it safe
			offset_limit = CL_UINT_MAX;
		}
		memset(&(wcd->match), 0, sizeof(cl_uchar16));
		// check for global_work_offset_limit here and adjust stride
		if ((wcd->work_offset + wcd->work_size) >= offset_limit) {
			WC_DEBUG("Work offset: %lu size: %lu for device[%u]\n",
					wcd->work_offset, wcd->work_size, devindex);
			wcd->stride += offset_limit;
			wcd->work_offset = wcd->work_offset + wcd->work_size -
								offset_limit;
			rc |= clSetKernelArg(wcd->kernel, wcd->stride_argc,
					sizeof(cl_ulong), &wcd->stride);
			WC_ERROR_OPENCL_BREAK(clSetKernelArg, rc);
			WC_DEBUG("Global work offset reset to %lu. Stride: %lu\n",
					wcd->work_offset, wcd->stride);
			WC_DEBUG("Reset for kernel number: %lu\n", wcu->kernelcounter);
		}
		// enqueue the mem-write for the device
		rc = clEnqueueWriteBuffer(dev->cmdq, wcd->mem, CL_FALSE,
				0, sizeof(cl_uchar16), &wcd->match, 0, NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueWriteBuffer, rc);
		// enqueue the kernel for the device
		rc = clEnqueueNDRangeKernel(dev->cmdq, wcd->kernel, workdim,
				&(wcd->work_offset), &(wcd->work_size), NULL,
				0, NULL, NULL);
		WC_ERROR_OPENCL_BREAK(clEnqueueNDRangeKernel, rc);
		// enqueue the mem-read for the device
		rc = clEnqueueReadBuffer(dev->cmdq, wcd->mem, CL_FALSE,
				0, sizeof(cl_uchar16), &wcd->match, 0, NULL,
				outevent);
		WC_ERROR_OPENCL_BREAK(clEnqueueReadBuffer, rc);
		wcu->kernelcounter++;
	} while (0);
	return (rc == CL_SUCCESS) ? WC_EXE_OK : WC_EXE_ERR_OPENCL;
}

wc_err_t crackmd5_on_device_range_done(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, wc_data_t *gdata,
		uint64_t start, uint64_t end)
{
	struct wc_user *wcu = (struct wc_user *)user;
	struct wc_per_device *wcd = NULL;
	if (!wc || !dev || !wcu)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!wcu->devices || devindex >= wcu->num_devices)
		return WC_EXE_ERR_BAD_STATE;
	// check for matches
	wcd = &wcu->devices[devindex];
	if (wcd->match.s[0] != 0) {
		int8_t l = 0;
		WC_INFO("Found match in %luth kernel call: ", wcu->kernelcounter);
		for (l = 0; l < wcd->nchars; ++l)
			WC_NULL("%c", wcd->match.s[l]);
		WC_NULL("\n");
		wcu->found = 1;
		memcpy(&wcu->match, &wcd->match, sizeof(wcd->match));
		return WC_EXE_ERR_ABORT;
	}
	return WC_EXE_OK;
}

wc_err_t crackmd5_on_device_finish(const wc_exec_t *wc, wc_cldev_t *dev,
		uint32_t devindex, void *user, wc_data_t *gdata)
{
	struct wc_user *wcu = (struct wc_user *)user;
	cl_int rc = CL_SUCCESS;
	struct wc_per_device *wcd = NULL;
	if (!wc || !dev || !wcu)
		return WC_EXE_ERR_INVALID_PARAMETER;
	if (!wcu->devices || devindex >= wcu->num_devices)
		return WC_EXE_ERR_BAD_STATE;

	// free the memory and other objects
	wcd = &wcu->devices[devindex];
	if (wcd->kernel) {
		rc = clReleaseKernel(wcd->kernel);
		wcd->kernel = (cl_kernel)0;
		if (rc != CL_SUCCESS)
			WC_ERROR_OPENCL(clReleaseMemObject, rc);
	}
	if (wcd->mem) {
		rc = clReleaseMemObject(wcd->mem);
		wcd->mem = (cl_mem)0;
		if (rc != CL_SUCCESS)
			WC_ERROR_OPENCL(clReleaseMemObject, rc);
	}
	return (rc == CL_SUCCESS) ? WC_EXE_OK : WC_EXE_ERR_OPENCL;
}

int main(int argc, char **argv)
{
	wc_err_t err = WC_EXE_OK;
	wc_exec_t *wc = NULL;
	struct wc_user user;
	wc_exec_callbacks_t callbacks;

	// print license
	WC_NULL("%s\n", wc_util_license());

	wc = wc_executor_init(&argc, &argv);
	assert(wc != NULL);
	do {
		struct timeval tv1, tv2;
		wc_util_timeofday(&tv1);
		memset(&user, 0, sizeof(user));
		if (wc_executor_system_id(wc) == 0) {
			if (wc_user_parse(argc, argv, &user) < 0) {
				WC_ERROR("Unable to parse arguments.\n");
				return -1;
			}
			wc_user_dump(&user);
		}
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
		callbacks.on_code_compile = crackmd5_on_compile;
		callbacks.get_global_data = crackmd5_get_global_data;
		callbacks.get_task_range_multiplier = crackmd5_get_multiplier;
		callbacks.on_device_start = crackmd5_on_device_start;
		callbacks.on_device_finish = crackmd5_on_device_finish;
		callbacks.on_device_range_exec = crackmd5_on_device_range_exec;
		callbacks.on_device_range_done = crackmd5_on_device_range_done;
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
		err = wc_executor_run(wc, 0);
		if (err != WC_EXE_OK) {
			WC_ERROR("Unable to crack MD5 sum. Error: %d\n", err);
			break;
		} else {
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
	wc_user_cleanup(&user);
	return (int)err;
}
