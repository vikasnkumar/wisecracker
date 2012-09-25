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
#ifndef __WISECRACKER_MACROS_H__
#define __WISECRACKER_MACROS_H__

#define WC_NULL(...) fprintf(stderr, __VA_ARGS__)
#define WC_DEBUG(...) \
do { \
	fprintf(stderr, "[%s:%d] DEBUG: ", __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
} while (0)
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

#ifdef WIN32
	#define WC_MALLOC(A) HeapAlloc(GetProcessHeap(),0,(A))
	#define WC_CALLOC(A,B) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,((A)*(B)))
	#define WC_REALLOC(A,B) HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(A),(B))
	#define WC_FREE(A) \
		do { \
			if ((A)) { \
				HeapFree(GetProcessHeap(), 0, (A)); \
				(A) = NULL; \
			} \
		} while (0)
	#define WC_STRCMPI _stricmp
	#define WC_STRNCMPI _strincmp
	#define snprintf _snprintf
	#define strdup _strdup
	#define WC_BASENAME PathFindFileName
#else
	#define WC_MALLOC(A) malloc((A))
	#define WC_CALLOC(A,B) calloc((A),(B))
	#define WC_REALLOC(A,B) realloc((A),(B))
	#define WC_FREE(A) \
		do { \
			if ((A)) \
			free((A)); \
			(A) = NULL; \
		} while (0)
	#define WC_STRCMPI strcasecmp
	#define WC_STRNCMPI strncasecmp
	#define WC_BASENAME basename
#endif

#define WC_OPENCL_OPTS "-Werror -I."

#define WC_TIME_TAKEN(TV1,TV2) \
	(double)(((TV2).tv_sec - (TV1).tv_sec) + (double)((TV2).tv_usec - (TV1).tv_usec) / 1000000)

#endif //__WISECRACKER_MACROS_H__

