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

int wc_mpi_init(int *argc, char ***argv);

int wc_mpi_finalize();

void wc_mpi_abort(int err);

int wc_mpi_peer_count();

int wc_mpi_peer_id();

#endif // __WISECRACKER_MPI_INTERNAL_H__
