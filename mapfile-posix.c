#ifndef __MINGW32__
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "mapfile.h"

struct MappedFile_s MappedFile_Create(char *filename, size_t size)
{
	__label__ out_error, out_ok, out_close;
	struct MappedFile_s m;

	m._fd = open(filename, O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
	if (!m._fd) goto out_error;
	close(m._fd);
	if (truncate(filename, size) < 0) goto out_error;
	m._fd = open(filename, O_RDWR);
	if (!m._fd) goto out_error;

	m.data = mmap(
		NULL,
		size,
		PROT_READ|PROT_WRITE,
		MAP_SHARED,
		m._fd,
		0
	);
	if (m.data == NULL) {
		goto out_close;
	}

	memset(m.data, 0, size);
	m.size = size;

	goto out_ok;

out_close:
	close(m._fd);
out_error:
	m.size = 0;
	m.data = NULL;
out_ok:
	return m;
}

struct MappedFile_s MappedFile_Open(char *filename, bool writable)
{
	__label__ out_error, out_ok, out_close;
	struct MappedFile_s m;
	struct stat sb;

	if (stat(filename, &sb) == -1) {
		goto out_error;
	}
	m.size = sb.st_size;

	m._fd = open(filename, writable ? O_RDWR : O_RDONLY);
	if (!m._fd) {
		goto out_error;
	}

	m.data = mmap(
		NULL,
		sb.st_size,
		PROT_READ|PROT_WRITE,
		writable ? MAP_SHARED : MAP_PRIVATE,
		m._fd,
		0
	);
	if (m.data == NULL) {
		goto out_close;
	}

	goto out_ok;

out_close:
	close(m._fd);
out_error:
	m.data = NULL;
out_ok:
	return m;
}

void MappedFile_Close(struct MappedFile_s m)
{
	munmap(m.data, m.size);
	close(m._fd);
}

/* __MINGW32__ */
#endif
