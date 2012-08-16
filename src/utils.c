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
