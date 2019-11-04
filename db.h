#ifndef _DB_H_
#define _DB_H_
#include <sqlite3.h>
#include <inttypes.h>
#include <stdio.h>
#include "pcode.h"

int DB_Init(sqlite3 **db, char *filename);
int DB_Close(sqlite3 *db);
int DB_Begin(sqlite3 *db);
int DB_End(sqlite3 *db);
int DB_AddFrag(
	sqlite3 *db,
	char *pcode,
	int64_t addr,
	int64_t num,
	int64_t ep,
	int64_t code,
	int64_t reloc,
	int64_t size,
	int64_t memsize,
	int64_t segment
);
int DB_GetSizeForNum(sqlite3 *db, int num);
int DB_GetAddrForNum(sqlite3 *db, int num);
int DB_FragSearch(sqlite3 *db, uint8_t *data, ssize_t size);
#endif
