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
