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
#ifndef __WISECRACKER_MACROS_H__
#define __WISECRACKER_MACROS_H__

#define WC_NULL(...) fprintf(stderr, __VA_ARGS__)
#define WC_INFO(...) \
do { \
	fprintf(stderr, "[%s:%d] INFO: ", __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
} while (0)

#define WC_WARN(...) \
do { \
	fprintf(stderr, "[%s:%d] WARN: ", __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
} while (0)

#define WC_ERROR(...) \
do { \
	fprintf(stderr, "[%s:%d] ERROR: ", __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
} while (0)

#define WC_ERROR_OUTOFMEMORY(A) \
	WC_ERROR("Out of host memory. Tried allocating %ld bytes.\n", (size_t)(A));

#define WC_ERROR_OPENCL(FN,RC) WC_ERROR(#FN "() Error: %d\n", (int)(RC))

#define WC_ERROR_OPENCL_BREAK(FN,RC) \
if ((RC) != CL_SUCCESS) { \
	WC_ERROR_OPENCL(FN,RC); \
	break; \
}

#define WC_MALLOC(A) malloc((A))
#define WC_FREE(A) \
do { \
    if ((A)) \
        free((A)); \
    (A) = NULL; \
} while (0)

#define WC_OPENCL_OPTS "-Werror -I."
#define WC_OPENCL_VERBOSE "-cl-nv-verbose"

#define WC_TIME_TAKEN(TV1,TV2) \
	(double)(((TV2).tv_sec - (TV1).tv_sec) + (double)((TV2).tv_usec - (TV1).tv_usec) / 1000000)

#endif //__WISECRACKER_MACROS_H__

