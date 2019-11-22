#ifdef __MINGW32__
#include <windows.h>
#include <inttypes.h>
#include <stdio.h>
#include "mapfile.h"

struct MappedFile_s MappedFile_Create(char *filename, size_t size)
{
	__label__ out_error, out_ok;
	LPVOID p;
	BOOL rc;
	LARGE_INTEGER liSize;
	struct MappedFile_s m;
	DWORD dw;
	char *lpMsgBuf;

	m._hFile = CreateFile(
		filename,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (m._hFile == INVALID_HANDLE_VALUE) {
		goto out_error;
	}

	liSize.QuadPart = size;
	m.size = size;
	rc = SetFilePointerEx(
		m._hFile,
		liSize,
		NULL,
		FILE_BEGIN
	);
	if (rc == 0) {
		goto out_error;
	}

	rc = SetEndOfFile(m._hFile);
	if (rc == 0) {
		goto out_error;
	}

	m._hMapping = CreateFileMapping(
		m._hFile,
		NULL,
		PAGE_READWRITE,
		liSize.HighPart,
		liSize.LowPart,
		NULL
	);

	if (m._hMapping == INVALID_HANDLE_VALUE) {
		goto out_error;
	}

	p = MapViewOfFile(
		m._hMapping,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		0
	);

	if (p == NULL) {
		goto out_error;
	}

	m.data = (void *) p;
	goto out_ok;

out_error:
	dw = GetLastError();
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0,
		NULL
	);
	printf("error in MappedFile_Create: %s", lpMsgBuf);
	LocalFree(lpMsgBuf);
	m.data = NULL;
out_ok:
	return m;
}

struct MappedFile_s MappedFile_Open(char *filename, bool writable)
{
	__label__ out_error, out_ok;
	LPVOID p;
	BOOL rc;
	LARGE_INTEGER liSize;
	struct MappedFile_s m;

	m._hFile = CreateFile(
		filename,
		writable ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (m._hFile == INVALID_HANDLE_VALUE) {
		goto out_error;
	}

	rc = GetFileSizeEx(m._hFile, &liSize);
	if (rc == 0) {
		goto out_error;
	}
	m.size = (uint64_t) liSize.QuadPart;

	m._hMapping = CreateFileMapping(
		m._hFile,
		NULL,
		writable ? PAGE_READWRITE : PAGE_READONLY,
		0,
		m.size,
		NULL
	);

	if (m._hMapping == INVALID_HANDLE_VALUE) {
		goto out_error;
	}

	p = MapViewOfFile(
		m._hMapping,
		writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_COPY,
		0,
		0,
		0
	);

	if (p == NULL) {
		goto out_error;
	}

	m.data = (void *) p;
	goto out_ok;

out_error:
	m.data = NULL;
out_ok:
	return m;
}

void MappedFile_Close(struct MappedFile_s m)
{
	FlushViewOfFile((LPCVOID) m.data, 0);
	UnmapViewOfFile((LPCVOID) m.data);
	CloseHandle(m._hMapping);
	CloseHandle(m._hFile);
}

/* __MINGW32__ */
#endif
