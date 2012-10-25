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
#include <wisecracker.h>
#include "internal_mpi.h"
#ifdef WC_MPI_H

#include <mpi.h>

#define WC_HANDLE_MPI_ERROR(FN,RC) \
	if ((RC) != MPI_SUCCESS) { \
		char errstr[MPI_MAX_ERROR_STRING]; \
		int errlen = MPI_MAX_ERROR_STRING; \
		memset(errstr, 0, errlen); \
		MPI_Error_string(rc, errstr, &errlen); \
		WC_ERROR(#FN " Error: %s\n", errstr); \
	}

int wc_mpi_init(int *argc, char ***argv)
{
	int rc = MPI_Init(argc, argv);
	WC_HANDLE_MPI_ERROR(MPI_Init, rc);
	return rc;
}

int wc_mpi_finalize()
{
	int rc = MPI_Finalize();
	WC_HANDLE_MPI_ERROR(MPI_Finalize, rc);
	return rc;
}

void wc_mpi_abort(int err)
{
	WC_DEBUG("Calling on MPI_Abort with error: %d\n", err);
	MPI_Abort(MPI_COMM_WORLD, err);
}

int wc_mpi_peer_count()
{
	int value = -1;
	int rc = MPI_Comm_size(MPI_COMM_WORLD, &value);
	WC_HANDLE_MPI_ERROR(MPI_Comm_size, rc);
	return (rc == MPI_SUCCESS) ? value : -1;
}

int wc_mpi_peer_id()
{
	int value = -1;
	int rc = MPI_Comm_rank(MPI_COMM_WORLD, &value);
	WC_HANDLE_MPI_ERROR(MPI_Comm_rank, rc);
	return (rc == MPI_SUCCESS) ? value : -1;
}

int wc_mpi_broadcast(void *buffer, int count, void *datatype, int id)
{
	int rc = MPI_Bcast(buffer, count, (MPI_Datatype)datatype, id,
						MPI_COMM_WORLD);
	WC_HANDLE_MPI_ERROR(MPI_Bcast, rc);
	return rc;
}

int wc_mpi_gather(void *sendbuf, int scount, void *sendtype, void *recvbuf,
					int rcount, void *recvtype, int master_id)
{
	if (sendbuf && recvbuf) {
		int rc = MPI_Gather(sendbuf, scount, sendtype, recvbuf, rcount,
						recvtype, master_id, MPI_COMM_WORLD);
		WC_HANDLE_MPI_ERROR(MPI_Gather, rc);
		return rc;
	}
	return -1;
}

int wc_mpi_scatter(void *sendbuf, int scount, void *sendtype, void *recvbuf,
				int rcount, void *recvtype, int master_id)
{
	if (sendbuf && recvbuf) {
		int rc = MPI_Scatter(sendbuf, scount, sendtype, recvbuf, rcount,
						recvtype, master_id, MPI_COMM_WORLD);
		WC_HANDLE_MPI_ERROR(MPI_Scatter, rc);
		return rc;
	}
	return -1;
}

int wc_mpi_iprobe(int src_id, int tag, int *flag, wc_mpistatus_t *status)
{
	int rc = MPI_Iprobe(src_id, tag, MPI_COMM_WORLD, flag, status);
	WC_HANDLE_MPI_ERROR(MPI_Iprobe, rc);
	return rc;
}

int wc_mpi_irecv(void *buffer, int count, void *datatype, int src_id, int tag,
				wc_mpirequest_t *req)
{
	if (buffer) {
		int rc = MPI_Irecv(buffer, count, datatype, src_id, tag,
							MPI_COMM_WORLD, req);
		WC_HANDLE_MPI_ERROR(MPI_Irecv, rc);
		return rc;
	}
	return -1;
}

int wc_mpi_isend(void *buffer, int count, void *datatype, int dest_id, int tag,
				wc_mpirequest_t *req)
{
	if (buffer) {
		int rc = MPI_Isend(buffer, count, datatype, dest_id, tag,
							MPI_COMM_WORLD, req);
		WC_HANDLE_MPI_ERROR(MPI_Isend, rc);
		return rc;
	}
	return -1;
}

int wc_mpi_test(wc_mpirequest_t *req, int *flag, wc_mpistatus_t *status)
{
	int rc = MPI_Test(req, flag, status);
	WC_HANDLE_MPI_ERROR(MPI_Test, rc);
	return rc;
}

#else

int wc_mpi_init(int *argc, char ***argv)
{
	return 0;
}

int wc_mpi_finalize()
{
	return 0;
}

void wc_mpi_abort(int err)
{
}

int wc_mpi_peer_count()
{
	return 1;
}

int wc_mpi_peer_id()
{
	return 0;
}

int wc_mpi_broadcast(void *buffer, int count, void *datatype, int id)
{
	return 0;
}

int wc_mpi_gather(void *sendbuf, int scount, void *sendtype, void *recvbuf,
				int rcount, void *recvtype, int master_id)
{
	return 0;
}

int wc_mpi_scatter(void *sendbuf, int scount, void *sendtype, void *recvbuf,
				int rcount, void *recvtype, int master_id)
{
	return 0;
}

int wc_mpi_iprobe(int src_id, int tag, int *flag, wc_mpistatus_t *status)
{
	if (flag)
		flag = 0;
	return 0;
}

int wc_mpi_irecv(void *buffer, int count, void *datatype, int src_id, int tag,
				wc_mpirequest_t *req)
{
	return 0;
}

int wc_mpi_isend(void *buffer, int count, void *datatype, int dest_id, int tag,
				wc_mpirequest_t *req)
{
	return 0;
}

int wc_mpi_test(wc_mpirequest_t *req, int *flag, wc_mpistatus_t *status)
{
	if (flag)
		flag = 0;
	return 0;
}

#endif
