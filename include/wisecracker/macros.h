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
	#define strdup wc_util_strdup
	#define WC_BASENAME PathFindFileNameA
	typedef HANDLE wc_thread_t;
	#define WC_THREAD_CREATE(A,FN,ARG) \
		((*(A) = CreateThread(NULL, 0, (FN), (ARG), 0, \
							  NULL)) != NULL ? 0 : -1)
	#define WC_THREAD_JOIN(A) WaitForSingleObject(*(A), 20 * 1000)
	#define WC_THREAD_KILL(A) TerminateThread(*(A), 0)
	#define WC_THREAD_DETACH(A) do { } while (0)
	#define WC_THREAD_RETURN DWORD
	typedef CRITICAL_SECTION wc_lock_t;
	#define WC_LOCK(A) EnterCriticalSection((A))
	#define WC_UNLOCK(A) LeaveCriticalSection((A))
	// create a recursive lock.
	#define WC_LOCK_CREATE(A,B) InitializeCriticalSection((A))
	#define WC_LOCK_DESTROY(A) DeleteCriticalSection((A))
	typedef struct {
		HANDLE event;
	} wc_signal_t;
	#define WC_SIGNAL_CREATE(A) \
	do { \
		if ((A)) { \
			(A)->event = CreateEvent(NULL, FALSE, FALSE, NULL); \
			if (!(A)->event) { \
				FC_LOG("Unable to create event. %x\n", GetLastError()); \
			} \
		} \
	} while (0)
	#define WC_SIGNAL_SET(A) \
	do { \
		if ((A) && (A)->event) \
		SetEvent((A)->event); \
	} while (0)
	#define WC_SIGNAL_DESTROY(A) \
	do { \
		if ((A) && (A)->event) { \
			CloseHandle((A)->event); \
			(A)->event = NULL; \
		} \
	} while (0)
	#define WC_SIGNAL_TIMEDOUT WAIT_TIMEOUT
	#define WC_SIGNAL_WAIT(A,PERIOD,RC) \
	do { \
		if ((A) && (A)->event) { \
			DWORD dw = 0; \
			dw = WaitForSingleObject((A)->event, \
					((PERIOD) > 0 ? (PERIOD) : INFINITE)); \
			if (dw != WAIT_OBJECT_0 && dw != WAIT_TIMEOUT) \
			(RC) = -1; \
			else \
			(RC) = dw; \
		} else { \
			(RC) = -1; \
		} \
	} while (0)
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
	typedef pthread_t wc_thread_t;
	#define WC_THREAD_CREATE(A,FN,ARG) pthread_create((A), NULL, (FN), (ARG))
	#define WC_THREAD_JOIN(A) pthread_join(*(A), NULL)
	#define WC_THREAD_KILL(A) pthread_cancel(*(A))
	#define WC_THREAD_DETACH(A) pthread_detach(*(A))
	#define WC_THREAD_RETURN void *
	typedef pthread_mutex_t wc_lock_t;
	#define WC_LOCK(A) pthread_mutex_lock((A))
	#define WC_UNLOCK(A) pthread_mutex_unlock((A))
	// create a recursive lock.
	#define WC_LOCK_CREATE(A,B) \
	do { \
		pthread_mutexattr_t mattr; \
		pthread_mutexattr_init(&mattr); \
		if ((B)) \
			pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE); \
		pthread_mutex_init((A), &mattr); \
		pthread_mutexattr_destroy(&mattr); \
	} while (0)
	#define WC_LOCK_DESTROY(A) pthread_mutex_destroy((A))
	typedef struct {
		pthread_cond_t cond;
		pthread_mutex_t mutex;
	} wc_signal_t;
	#define WC_SIGNAL_CREATE(A) \
	do { \
		FC_LOCK_CREATE(&((A)->mutex), false); \
		pthread_cond_init(&((A)->cond), NULL); \
	} while (0)
	#define WC_SIGNAL_SET(A) \
	do { \
		FC_LOCK(&((A)->mutex)); \
		pthread_cond_signal(&((A)->cond)); \
		FC_UNLOCK(&((A)->mutex)); \
	} while (0)
	#define WC_SIGNAL_DESTROY(A) \
	do { \
		pthread_cond_destroy(&((A)->cond)); \
		FC_LOCK_DESTROY(&((A)->mutex)); \
	} while (0)
	#define WC_SIGNAL_TIMEDOUT ETIMEDOUT
	#define WC_SIGNAL_WAIT(A,PERIOD,RC) \
	do { \
		if (PERIOD > 0) { \
			struct timespec ts; \
			struct timeval tv; \
			gettimeofday(&tv, NULL); \
			ts.tv_sec = tv.tv_sec; \
			ts.tv_nsec = tv.tv_usec * 1000; \
			ts.tv_sec += PERIOD; \
			RC = pthread_cond_timedwait(&((A)->cond), &((A)->mutex), &ts); \
			FC_UNLOCK(&((A)->mutex)); \
		} else { \
			RC = pthread_cond_wait(&((A)->cond), &((A)->mutex)); \
			FC_UNLOCK(&((A)->mutex)); \
		} \
	} while (0)
#endif

#define WC_OPENCL_OPTS "-Werror -I."

#define WC_TIME_TAKEN(TV1,TV2) \
	(double)(((TV2).tv_sec - (TV1).tv_sec) + (double)((TV2).tv_usec - (TV1).tv_usec) / 1000000)

#endif //__WISECRACKER_MACROS_H__
