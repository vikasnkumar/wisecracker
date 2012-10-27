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
#include <wisecracker.h>

volatile int wc_log_level = WC_LOGLEVEL_DEBUG;

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

const char *wc_util_license()
{
	static const char __wc_util_license[] = 
    "Wisecracker:  Copyright (C) 2011-2012. Vikas N Kumar, Selective Intellect"\
	" LLC.\nThis program comes with ABSOLUTELY NO WARRANTY.\n"\
	"This is free software, and you are welcome to redistribute it "\
	"under certain conditions.\nRead the GPLv3 license provided with the "\
	"source code for more details.\n";
	return __wc_util_license;
}

const char *wc_util_charset_tostring(wc_util_charset_t chs)
{
	switch (chs) {
	case WC_UTIL_CHARSET_ALNUM: return "alnum";
	case WC_UTIL_CHARSET_ALPHA: return "alpha";
	case WC_UTIL_CHARSET_DIGIT: return "digit";
	case WC_UTIL_CHARSET_SPECIAL: return "special";
	case WC_UTIL_CHARSET_ALNUMSPL: return "alnumspl";
	default:
		WC_WARN("Invalid charset given.\n");
		return "unknown";
	}
}

wc_util_charset_t wc_util_charset_fromstring(const char *str)
{
	if (WC_STRCMPI(str, "alnum") == 0) {
		return WC_UTIL_CHARSET_ALNUM;
	} else if (WC_STRCMPI(str, "alpha") == 0) {
		return WC_UTIL_CHARSET_ALPHA;
	} else if (WC_STRCMPI(str, "alnumspl") == 0) {
		return WC_UTIL_CHARSET_ALNUMSPL;
	} else if (WC_STRCMPI(str, "digit") == 0) {
		return WC_UTIL_CHARSET_DIGIT;
	} else if (WC_STRCMPI(str, "special") == 0) {
		return WC_UTIL_CHARSET_SPECIAL;
	} else {
		WC_WARN("Unknown charset %s given. Using the default.\n",
				str);
	}
	return WC_UTIL_CHARSET_ALNUM;
}

size_t wc_util_charset_size(wc_util_charset_t chs)
{
	switch (chs) {
	case WC_UTIL_CHARSET_ALPHA: return WC_UTIL_CHARSET_ALPHA_SZ;
	case WC_UTIL_CHARSET_DIGIT: return WC_UTIL_CHARSET_DIGIT_SZ;
	case WC_UTIL_CHARSET_ALNUM: return WC_UTIL_CHARSET_ALNUM_SZ;
	case WC_UTIL_CHARSET_SPECIAL: return WC_UTIL_CHARSET_SPECIAL_SZ;
	case WC_UTIL_CHARSET_ALNUMSPL: return WC_UTIL_CHARSET_ALNUMSPL_SZ;
	default:
		WC_WARN("Invalid charset given.\n");
		return 0;
	}
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
int wc_util_timeofday(struct timeval *tv)
{
	return gettimeofday(tv, NULL);
}
#endif

char *wc_util_strdup(const char *str)
{
	char *out = NULL;
	if (str) { 
		size_t len = strlen(str);
		out = WC_MALLOC(len + 1);
		if (!out) {
			WC_ERROR_OUTOFMEMORY(len + 1);
		} else {
			memcpy(out, str, len);
			out[len] = 0x0;
		}
	}
	return out;
}
