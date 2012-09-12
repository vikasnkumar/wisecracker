/*
Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of Selective Intellect LLC nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * Copyright: 2011. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 21st Dec 2011
 * Software: WiseCracker
 */
#ifndef __WISECRACKER_RUNTIME_H__
#define __WISECRACKER_RUNTIME_H__

EXTERN_C_BEGIN

typedef struct wc_device_t__ wc_device_t;

typedef struct {
	struct wc_device_t__ {
		cl_device_id id;
		cl_platform_id platform;
		cl_device_type type;
		cl_uint compute_units;
		size_t workgroup_sz;
		cl_uint workitem_dim;
		size_t *workitem_sz;
		cl_ulong allocmem_sz;
		cl_ulong globalmem_sz;
		cl_ulong constmem_sz;
		cl_ulong localmem_sz;
		char *pl_name;
		char *pl_ext;
		char *pl_version;
		char *pl_profile;
		char *pl_vendor;
		cl_context context;
		cl_command_queue cmdq;
		cl_program program;
	} *devices;
	uint32_t device_index;
	uint32_t device_max;
} wc_runtime_t;


#define WC_DEVICE_CPU 0x0
#define WC_DEVICE_GPU 0x1
#define WC_DEVICE_ANY 0x2

/* the flag can take values WC_DEVICE_CPU, WC_DEVICE_GPU or WC_DEVICE_ANY
 * Any other value is interpreted as WC_DEVICE_ANY.
 */
WCDLL wc_runtime_t *wc_runtime_create(uint32_t devicetype, uint32_t max_devices);

WCDLL void wc_runtime_destroy(wc_runtime_t *wc);

WCDLL void wc_runtime_dump(const wc_runtime_t *wc);

WCDLL int wc_runtime_program_load(wc_runtime_t *wc, const char *src, size_t len,
							const char *buildopts, int verbose);

WCDLL uint8_t wc_runtime_is_usable(const wc_runtime_t *wc);
	
EXTERN_C_END

#endif //__WISECRACKER_RUNTIME_H__

