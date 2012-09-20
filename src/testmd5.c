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
#include <wisecracker/config.h>
#define ON_CPU
#ifdef ON_CPU
	#define __global
	#define __local
	#define __constant
	#define __kernel
	#define uchar cl_uchar
	#define uint cl_uint
	typedef struct {
		uint s0;
		uint s1;
		uint s2;
		uint s3;
	} uint4;
	typedef struct {
		uint s0;
		uint s1;
	} uint2;
	#define get_global_id(A) (0)
#endif

#include "md5.cl"

int main(int argc, char **argv)
{
	cl_uchar buf[512];
	cl_uchar digest[16];
	cl_uchar l_buf[512];
	cl_uint kdx;

	for (kdx = 0; kdx < sizeof(buf); ++kdx)
		buf[kdx] = (cl_uchar)(kdx & 0xFF);
	md5sum(buf, NULL, digest, 1, l_buf, (cl_uint)sizeof(l_buf));
	for (kdx = 0; kdx < 16; ++kdx)
		printf("%02x\n", digest[kdx]);
	return 0;
}
