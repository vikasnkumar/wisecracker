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
#ifndef __WC_GETOPT_H__
#define __WC_GETOPT_H__

#include <wisecracker/config.h>

#ifdef WC_GETOPT_H
	#include <getopt.h>
#else
	EXTERN_C_BEGIN
		extern char *optarg;
		extern int optind, opterr;
		int getopt(int argc, char **argv, char *optstr);
	EXTERN_C_END
#endif // WC_GETOPT_H

#endif // __WC_GETOPT_H__
