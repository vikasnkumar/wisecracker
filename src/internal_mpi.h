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
 * Copyright: 2011. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 16th Oct 2012
 * Software: WiseCracker
 */
#ifndef __WISECRACKER_MPI_INTERNAL_H__
#define __WISECRACKER_MPI_INTERNAL_H__

#ifdef WC_MPI_H
	#include <mpi.h>
	typedef MPI_Status wc_mpistatus_t;
	typedef MPI_Request wc_mpirequest_t;
#else
	#ifndef MPI_BYTE
		#define MPI_BYTE (void *)0
	#endif
	#ifndef MPI_INT
		#define MPI_INT (void *)0
	#endif
	#ifndef MPI_UNSIGNED_LONG_LONG
		#define MPI_UNSIGNED_LONG_LONG (void *)0
	#endif
	#ifndef MPI_UNSIGNED
		#define MPI_UNSIGNED (void *)0
	#endif
	#ifndef MPI_ANY_TAG
		#define MPI_ANY_TAG -1
	#endif
	#ifndef MPI_ANY_SOURCE
		#define MPI_ANY_SOURCE -1
	#endif
	typedef struct {
		void *ptr; /* just like that */
	} wc_mpistatus_t;
	#ifndef MPI_STATUS_IGNORE
		#define MPI_STATUS_IGNORE (wc_mpistatus_t *)0
	#endif
	typedef wc_mpistatus_t wc_mpirequest_t;
	#ifndef MPI_REQUEST_NULL
		#define MPI_REQUEST_NULL (wc_mpirequest_t *)0
	#endif
#endif

int wc_mpi_init(int *argc, char ***argv);

int wc_mpi_finalize();

void wc_mpi_abort(int err);

int wc_mpi_peer_count();

int wc_mpi_peer_id();

int wc_mpi_broadcast(void *buffer, int count, void *datatype, int id);

int wc_mpi_gather(void *sendbuf, int scount, void *sendtype, void *recvbuf,
					int rcount, void *recvtype, int master_id);

int wc_mpi_scatter(void *sendbuf, int scound, void *sendtype, void *recvbuf,
					int rcount, void *recvtype, int master_id);

int wc_mpi_iprobe(int src_id, int tag, int *flag, wc_mpistatus_t *status);

int wc_mpi_irecv(void *buffer, int count, void *datatype, int src_id, int tag,
				wc_mpirequest_t *req);

int wc_mpi_isend(void *buffer, int count, void *datatype, int dest_id, int tag,
				wc_mpirequest_t *req);

int wc_mpi_test(wc_mpirequest_t *req, int *flag, wc_mpistatus_t *status);

#endif // __WISECRACKER_MPI_INTERNAL_H__
