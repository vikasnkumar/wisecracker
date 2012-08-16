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
