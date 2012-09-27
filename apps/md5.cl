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
/*
 * This code is based on RFC 1321.
 */

typedef struct {
	uint4 state;
	uint2 count;
	uchar buffer[64];
} MD5_CTX;

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* MAC OSX's OpenCL compiler need prototypes pre-defined. */
void md5_decode_private_64(uint *outp, const uchar *inp);
void md5_decode_constant_64(uint *outp, __constant const uchar *inp);
void md5_decode_local_64(uint *outp, __local const uchar *inp);
void md5_transform_private(MD5_CTX *, const uchar *);
void md5_transform_local(MD5_CTX *, __local const uchar *);
void md5_transform_constant(MD5_CTX *, __constant const uchar *);
void md5_transform_internal(MD5_CTX *, const uint *);
void md5_init(MD5_CTX *ctx);
void md5_update_private(MD5_CTX *ctx, const uchar *input, uint inputlen);
void md5_update_local(MD5_CTX *ctx, __local const uchar *input, uint inputlen);
void md5_update_constant(MD5_CTX *ctx, __constant const uchar *input,
							uint inputlen);
void md5_final(MD5_CTX *ctx, __local uchar *digest);

#define MD5_MEMCPY(OUTPUT,INPUT,LEN) \
do { \
	for (uint k = 0; k < (LEN); ++k) \
		(OUTPUT)[k] = (INPUT)[k]; \
} while (0)

/* unrolled already by design */
#define MD5_ENCODE_UINT2(OUT,IN) \
do { \
	OUT[0] = (uchar)(IN.s0 & 0xFF); \
	OUT[1] = (uchar)((IN.s0 >> 8) & 0xFF); \
	OUT[2] = (uchar)((IN.s0 >> 16) & 0xFF); \
	OUT[3] = (uchar)((IN.s0 >> 24) & 0xFF); \
	OUT[4] = (uchar)(IN.s1 & 0xFF); \
	OUT[5] = (uchar)((IN.s1 >> 8) & 0xFF); \
	OUT[6] = (uchar)((IN.s1 >> 16) & 0xFF); \
	OUT[7] = (uchar)((IN.s1 >> 24) & 0xFF); \
} while (0)

#define MD5_ENCODE_UINT4(OUT,IN) \
do { \
	OUT[0] = (uchar)(IN.s0 & 0xFF); \
	OUT[1] = (uchar)((IN.s0 >> 8) & 0xFF); \
	OUT[2] = (uchar)((IN.s0 >> 16) & 0xFF); \
	OUT[3] = (uchar)((IN.s0 >> 24) & 0xFF); \
	OUT[4] = (uchar)(IN.s1 & 0xFF); \
	OUT[5] = (uchar)((IN.s1 >> 8) & 0xFF); \
	OUT[6] = (uchar)((IN.s1 >> 16) & 0xFF); \
	OUT[7] = (uchar)((IN.s1 >> 24) & 0xFF); \
	OUT[8] = (uchar)(IN.s2 & 0xFF); \
	OUT[9] = (uchar)((IN.s2 >> 8) & 0xFF); \
	OUT[10] = (uchar)((IN.s2 >> 16) & 0xFF); \
	OUT[11] = (uchar)((IN.s2 >> 24) & 0xFF); \
	OUT[12] = (uchar)(IN.s3 & 0xFF); \
	OUT[13] = (uchar)((IN.s3 >> 8) & 0xFF); \
	OUT[14] = (uchar)((IN.s3 >> 16) & 0xFF); \
	OUT[15] = (uchar)((IN.s3 >> 24) & 0xFF); \
} while (0)

/* The following macros are copied from the RFC */
/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 Initialization. Load the magic numbers */
void md5_init(MD5_CTX *ctx)
{
	ctx->count = (uint2)(0);
	ctx->state.s0 = 0x67452301;
	ctx->state.s1 = 0xefcdab89;
	ctx->state.s2 = 0x98badcfe;
	ctx->state.s3 = 0x10325476;
	#pragma unroll 64
	for (uint i = 0; i < 64; ++i)
		ctx->buffer[i] = 0;
}

#define MD5_UPDATE_INTERNAL(TYPE) \
do { \
	uint index, i, partlen; \
	/* compute number of bytes mod 64 */ \
	index = (uint)((ctx->count.s0 >> 3) & 0x3F); \
	/* update number of bits */ \
	if ((ctx->count.s0 += ((uint)inputlen << 3)) < ((uint)inputlen << 3)) \
		ctx->count.s1++; \
	ctx->count.s1 += ((uint)inputlen >> 29); \
	partlen = 64 - index; \
	/* transform as many times as possible */ \
	if (inputlen >= partlen) { \
		MD5_MEMCPY(&ctx->buffer[index], input, partlen); \
		md5_transform_private(ctx, ctx->buffer); \
		for (i = partlen; (i + 63) < inputlen; i += 64) \
			md5_transform_ ##TYPE (ctx, &input[i]); \
		index = 0; \
	} else { \
		i = 0; \
	} \
	/* buffer remaining input */ \
	MD5_MEMCPY(&ctx->buffer[index], &input[i], inputlen - i); \
} while (0)

void md5_update_private(MD5_CTX *ctx, const uchar *input, uint inputlen)
{
	MD5_UPDATE_INTERNAL(private);
}

void md5_update_local(MD5_CTX *ctx, __local const uchar *input, uint inputlen)
{
	MD5_UPDATE_INTERNAL(local);
}

void md5_update_constant(MD5_CTX *ctx, __constant const uchar *input, uint inputlen)
{
	MD5_UPDATE_INTERNAL(constant);
}

__constant uchar PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void md5_final(MD5_CTX *ctx, __local uchar *digest)
{
	uchar bits[8];
	uint index, padlen;
/* save number of bits */
	MD5_ENCODE_UINT2(bits, ctx->count);
	/* pad out to 56 mod 64 */
	index = (uint)((ctx->count.s0 >> 3) & 0x3F);
	padlen = (index < 56) ? (56 - index) : (120 - index);
	md5_update_constant(ctx, PADDING, padlen);
	/* append length before padding */
	md5_update_private(ctx, bits, 8);
	/* store state in digest */
	MD5_ENCODE_UINT4(digest, ctx->state);
	/* zeroize sensitive information */
	ctx->state = (uint4)(0);
	ctx->count = (uint2)(0);
	#pragma unroll 64
	for (uint i = 0; i < 64; ++i)
		ctx->buffer[i] = 0;
}

void md5_decode_local_64(uint *outp, __local const uchar *inp)
{
	#pragma unroll 64
	for (uint k = 0, j = 0; j < 64; ++k, j += 4)
		outp[k] = ((uint)inp[j]) | (((uint)inp[j + 1]) << 8) |
			(((uint)inp[j + 2]) << 16) | (((uint)inp[j + 3]) << 24);
}

void md5_decode_constant_64(uint *outp, __constant const uchar *inp)
{
	#pragma unroll 64
	for (uint k = 0, j = 0; j < 64; ++k, j += 4)
		outp[k] = ((uint)inp[j]) | (((uint)inp[j + 1]) << 8) |
			(((uint)inp[j + 2]) << 16) | (((uint)inp[j + 3]) << 24);
}

void md5_decode_private_64(uint *outp, const uchar *inp)
{
	#pragma unroll 64
	for (uint k = 0, j = 0; j < 64; ++k, j += 4)
		outp[k] = ((uint)inp[j]) | (((uint)inp[j + 1]) << 8) |
			(((uint)inp[j + 2]) << 16) | (((uint)inp[j + 3]) << 24);
}

void md5_transform_local(MD5_CTX *ctx, __local const uchar *block)
{
	uint x[16];

	md5_decode_local_64(x, block);

	md5_transform_internal(ctx, x);
	/* zeroize sensitive info */
	#pragma unroll 16
	for (uint i = 0; i < 16; ++i)
		x[i] = 0;
}

void md5_transform_constant(MD5_CTX *ctx, __constant const uchar *block)
{
	uint x[16];

	md5_decode_constant_64(x, block);

	md5_transform_internal(ctx, x);

	/* zeroize sensitive info */
	#pragma unroll 16
	for (uint i = 0; i < 16; ++i)
		x[i] = 0;
}

void md5_transform_private(MD5_CTX *ctx, const uchar *block)
{
	uint x[16];

	md5_decode_private_64(x, block);
	
	md5_transform_internal(ctx, x);

	/* zeroize sensitive info */
	#pragma unroll 16
	for (uint i = 0; i < 16; ++i)
		x[i] = 0;
}

void md5_transform_internal(MD5_CTX *ctx, const uint *x)
{
	uint a, b, c, d;
	a = ctx->state.s0;
	b = ctx->state.s1;
	c = ctx->state.s2;
	d = ctx->state.s3;

	/* Round 1 */
	FF(a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH(a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II(a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	ctx->state.s0 += a;
	ctx->state.s1 += b;
	ctx->state.s2 += c;
	ctx->state.s3 += d;
}

#ifndef MAX_BLOCK_LEN
	#define MAX_BLOCK_LEN 512
#endif
__kernel void wc_md5sum(__global uchar *input, /* complete set of buffer blocks */
					__global uint *inputlen, /* block length. Max 512 each */
					__global uchar16 *digest, /* output MD5 digests. 16 each */
					uint count, /* max number of blocks */
					__local uchar *l_buf, /* local buffer */
					uint l_bufsz /* max local buffer length */
					)
{
	const uint index = get_global_id(0);
	MD5_CTX ctx;
	__local uchar out[16];

	if (index > count)
		return;
	if (l_bufsz < MAX_BLOCK_LEN)
		return;

	#pragma unroll MAX_BLOCK_LEN
	for (uint i = 0; i < MAX_BLOCK_LEN; ++i)
		l_buf[i] = input[i + index * MAX_BLOCK_LEN];
	md5_init(&ctx);
	md5_update_local(&ctx, l_buf, inputlen[index]);
	md5_final(&ctx, out);
	digest[index] = vload16(0, out);
}

__constant uchar WC_CHARSET_ALNUMSPL[94] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '~', '!',
	'@', '#', '$', '%', '^', '&', '*', '(',
	')', '_', '-', '+', '=', '/', '|', '\\',
	'?', '<', '>', '.', ',', ';', ':', '`',
	0x22, 0x27, '[', ']', '{', '}'
	// 0x27 is the single quote and 0x22 is the double quote
};

// this is taken from include/wisecracker/utils.h
// if that enum changes this should change accordingly
#define WC_UTIL_CHARSET_ALPHA 0
#define WC_UTIL_CHARSET_DIGIT 1
#define WC_UTIL_CHARSET_ALNUM 2
#define WC_UTIL_CHARSET_SPECIAL 3
#define	WC_UTIL_CHARSET_ALNUMSPL 4

#define WC_UTIL_CHARSET_ALPHA_SZ 52
#define WC_UTIL_CHARSET_DIGIT_SZ 10
#define WC_UTIL_CHARSET_ALNUM_SZ 62
#define WC_UTIL_CHARSET_SPECIAL_SZ 32
#define	WC_UTIL_CHARSET_ALNUMSPL_SZ 94

__constant ulong WC_DIVISORS_ALPHA[] = {
	1, // 52 ^ 0
	52, // 52 ^ 1
	2704, // 52 ^ 2
	140608, // 52 ^ 3
	7311616, // 52 ^ 4
	380204032, // 52 ^ 5
	19770609664, // 52 ^ 6
	1028071702528, // 52 ^ 7
	53459728531456, // 52 ^ 8
	2779905883635712, // 52 ^ 9
	144555105949057024 // 52 ^ 10
};
__constant ulong WC_DIVISORS_DIGIT[] = {
	1, // 10 ^ 0
	10, // 10 ^ 1
	100, // 10 ^ 2
	1000, // 10 ^ 3
	10000, // 10 ^ 4
	100000, // 10 ^ 5
	1000000, // 10 ^ 6
	10000000, // 10 ^ 7
	100000000, // 10 ^ 8
	1000000000, // 10 ^ 9
	10000000000 // 10 ^ 10
};
__constant ulong WC_DIVISORS_ALNUM[] = {
	1, // 62 ^ 0
	62, // 62 ^ 1
	3844, // 62 ^ 2
	238328, // 62 ^ 3
	14776336, // 62 ^ 4
	916132832, // 62 ^ 5
	56800235584, // 62 ^ 6
	3521614606208, // 62 ^ 7
	218340105584896, // 62 ^ 8
	13537086546263552, // 62 ^ 9
	839299365868340224 // 62 ^ 10
};
__constant ulong WC_DIVISORS_SPECIAL[] = {
	1, // 32 ^ 0
	32, // 32 ^ 1
	1024, // 32 ^ 2
	32768, // 32 ^ 3
	1048576, // 32 ^ 4
	33554432, // 32 ^ 5
	1073741824, // 32 ^ 6
	34359738368, // 32 ^ 7
	1099511627776, // 32 ^ 8
	35184372088832, // 32 ^ 9
	1125899906842624, // 32 ^ 10
	36028797018963968, // 32 ^ 11
	1152921504606846976 // 32 ^ 12
};
__constant ulong WC_DIVISORS_ALNUMSPL[] = {
	1, // 94 ^ 0
	94, // 94 ^ 1
	8836, // 94 ^ 2
	830584, // 94 ^ 3
	78074896, // 94 ^ 4
	7339040224, // 94 ^ 5
	689869781056, // 94 ^ 6
	64847759419264, // 94 ^ 7
	6095689385410816, // 94 ^ 8
	572994802228616704 // 94 ^ 9
};

__kernel void wc_md5sum_check_8(uchar8 input, /* starting portion of the string */
					uchar16 digest, /* MD5 digest to compare */
					__global uchar8 *matches, /* matching string output */
					uint charset_type, /* charset type */
					ulong stride, /* maximum stride */
					ulong2 idxrange /* index range */
					)
{
	__constant ulong *divisors = WC_DIVISORS_ALNUMSPL;
	__constant uchar *charset = WC_CHARSET_ALNUMSPL;
	uint charset_sz = WC_UTIL_CHARSET_ALNUMSPL_SZ;

	if (get_global_id(0) > stride)
		return;
	switch (charset_type) {
	case WC_UTIL_CHARSET_ALPHA:
		divisors = WC_DIVISORS_ALPHA;
		charset = WC_CHARSET_ALNUMSPL;
		charset_sz = WC_UTIL_CHARSET_ALPHA_SZ;
		break;
	case WC_UTIL_CHARSET_DIGIT:
		divisors = WC_DIVISORS_DIGIT;
		charset = &WC_CHARSET_ALNUMSPL[52];
		charset_sz = WC_UTIL_CHARSET_DIGIT_SZ;
		break;
	case WC_UTIL_CHARSET_ALNUM:
		divisors = WC_DIVISORS_ALNUM;
		charset = WC_CHARSET_ALNUMSPL;
		charset_sz = WC_UTIL_CHARSET_ALNUM_SZ;
		break;
	case WC_UTIL_CHARSET_SPECIAL:
		divisors = WC_DIVISORS_SPECIAL;
		charset = &WC_CHARSET_ALNUMSPL[62];
		charset_sz = WC_UTIL_CHARSET_SPECIAL_SZ;
		break;
	case WC_UTIL_CHARSET_ALNUMSPL:
		divisors = WC_DIVISORS_ALNUMSPL;
		charset = WC_CHARSET_ALNUMSPL;
		charset_sz = WC_UTIL_CHARSET_ALNUMSPL_SZ;
	default: // use the defaults set up earlier
		break;
	}

	__local uchar dig[16];
	// load the given md5 digest into array only once.
	vstore16(digest, 0, dig);
	for (int j = idxrange.s0; j < idxrange.s1; ++j) {
		MD5_CTX ctx;
		__local uchar out[16];
		uchar buf[8];
		uchar indices[8]; // each value is in [0. 64) so uchar is enough
		short flag;
		ulong id = get_global_id(0);
		id += stride * j; // for multiple kernel invocations
		#pragma unroll 8
		for (int i = 0; i < 8; ++i) {
			indices[i] = (id / divisors[i]) % charset_sz;
		}
		vstore8(input, 0, buf);
		#pragma unroll 8
		for (int i = 7; i >= 0; --i) {
			if (buf[i] == 0) {
				buf[i] = charset[indices[7 - i]];
			}
		}

		md5_init(&ctx);
		md5_update_private(&ctx, buf, 8);
		md5_final(&ctx, out);
		// check if it matches with digest
		flag = 0;
		#pragma unroll 16
		for (int i = 0; i < 16; ++i)
			flag |= (dig[i] - out[i]);
		if (flag == 0) {
			matches[0] = vload8(0, buf);
			break;
		}
	}
}
