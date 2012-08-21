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
#include <wisecracker.h>

int wc_util_glob_file(const char *filename, unsigned char **outdata,
					size_t *outlen)
{
	size_t fsz = 0;
	struct stat sb = { 0 };
	unsigned char *buf = NULL;
	int rc = 0;
	FILE *fp = NULL;
	if (!filename || !outlen || !outdata)
		return -1;
	if (stat(filename, &sb) >= 0) {
		fsz = sb.st_size;
	} else {
		int err = errno;
		WC_ERROR("Error getting file size for %s. Error: %s\n", filename,
				strerror(err));
		return -1;
	}
	if (fsz == 0) {
		WC_INFO("File size of %s is 0.\n", filename);
		*outlen = 0;
		*outdata = NULL;
		return 0;
	}
	buf = WC_MALLOC(fsz);
	if (!buf) {
		WC_ERROR_OUTOFMEMORY(fsz);
		return -1;
	}
	fp = fopen(filename, "rb");
	if (fp) {
		if (fread(buf, 1, fsz, fp) < fsz) {
			if (ferror(fp)) {
				WC_ERROR("Error reading the whole file %s.\n", filename);
				rc = -1;
			}
		}
		fclose(fp);
		if (rc >= 0) {
			*outlen = fsz;
			*outdata = buf;
			buf = NULL;
			rc = 0;
		}
	} else {
		int err = errno;
		WC_ERROR("Error opening file %s. Error: %s\n", filename,
				strerror(err));
		rc = -1;
	}
	WC_FREE(buf);
	return rc;
}

#ifndef WC_SYSTIME_H
int wc_util_timeofday(struct timeval *tv)
{
	if (tv) {
		struct _timeb tb = { 0 };
		_ftime_s(&tb);
		tv->tv_sec = (long)tb.time;
		tv->tv_usec = (long)tb.millitm * 1000;
		return 0;
	}
	return -1;
}
#else

#define wc_util_timeofday(A) gettimeofday((A), NULL)

#endif
