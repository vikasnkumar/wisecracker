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
#ifndef __WISECRACKER_UTILS_H__
#define __WISECRACKER_UTILS_H__

EXTERN_C_BEGIN

typedef enum {
	WC_UTIL_CHARSET_ALPHA = 0,
	WC_UTIL_CHARSET_DIGIT,
	WC_UTIL_CHARSET_ALNUM,
	WC_UTIL_CHARSET_SPECIAL,
	WC_UTIL_CHARSET_ALNUMSPL
} wc_util_charset_t;
/* provide a string name for the charset enum entry */
WCDLL const char *wc_util_charset_tostring(wc_util_charset_t chs);

WCDLL size_t wc_util_charset_size(wc_util_charset_t chs);

/* load a full file into a character buffer */
WCDLL int wc_util_glob_file(const char *filename, unsigned char **outdata,
						size_t *outlen);

/* cross platform time-of-day retrieval function */
WCDLL int wc_util_timeofday(struct timeval *tv);

/* useful if you want to print the license of the code */
WCDLL const char *wc_util_license();

/* cross platform and cross-DLL compatible strdup */
WCDLL char *wc_util_strdup(const char *str);

EXTERN_C_END

#endif //__WISECRACKER_UTILS_H__

