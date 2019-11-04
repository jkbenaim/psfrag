#include <arpa/inet.h>
#include <ctype.h>
#include "db.h"
#include "fragment.h"

int DB_Init(sqlite3 **db, char *filename) {
	int rc = SQLITE_OK;
	rc = sqlite3_open(filename, db);
	if (rc != SQLITE_OK) return rc;

	rc = sqlite3_exec(*db,
		"CREATE TABLE IF NOT EXISTS frags(pcode text, addr int, num int, ep int, code int, reloc int, size int, memsize int, segment int);",
		NULL, NULL, NULL
	);
	if (rc != SQLITE_OK) return rc;
	return SQLITE_OK;
}

int DB_Close(sqlite3 *db) {
	int rc = SQLITE_OK;
	rc = sqlite3_close(db);
	return rc;
}

int DB_Begin(sqlite3 *db) {
	return sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
}

int DB_End(sqlite3 *db) {
	return sqlite3_exec(db, "END;", NULL, NULL, NULL);
}

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
) {
	__label__ err_prepare, err_bind, err_step;
	int rc = SQLITE_OK;
	char *zErr = NULL;
	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(
		db,
		R"STATEMENT(
			insert
			into frags(
				pcode,
				addr,
				num,
				ep,
				code,
				reloc,
				size,
				memsize,
				segment
			)
			values(
				:pcode,
				:addr,
				:num,
				:ep,
				:code,
				:reloc,
				:size,
				:memsize,
				:segment
			);
		)STATEMENT",
		-1,
		&stmt,
		NULL
	);
	if (rc != SQLITE_OK) goto err_prepare;

	rc = sqlite3_bind_text(stmt, 1, pcode, -1, SQLITE_TRANSIENT);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_bind_int64(stmt, 2, addr);
	if (rc != SQLITE_OK) goto err_bind;
	
	rc = sqlite3_bind_int64(stmt, 3, num);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_bind_int64(stmt, 4, ep);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_bind_int64(stmt, 5, code);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_bind_int64(stmt, 6, reloc);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_bind_int64(stmt, 7, size);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_bind_int64(stmt, 8, memsize);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_bind_int64(stmt, 9, segment);
	if (rc != SQLITE_OK) goto err_bind;

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) goto err_step;

	sqlite3_finalize(stmt);
	return SQLITE_OK;

err_step:
	if (!zErr) zErr = "error in step";
err_bind:
	if (!zErr) zErr = "error in bind";
	sqlite3_finalize(stmt);
err_prepare:
	if (!zErr) zErr = "error in prepare";

	if (!zErr) fprintf(stderr, "DB_AddFrag: %s\n", zErr);
	return rc;
}

int DB_GetSizeForNum(sqlite3 *db, int num)
{
	__label__ out_finalize;
	char *zErr = NULL;
	int rc = SQLITE_OK;
	int addr = -1;

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(
		db,
		R"STATEMENT(
			select size from frags where num==:num limit 1;
		)STATEMENT",
		-1,
		&stmt,
		NULL
	);
	if (rc != SQLITE_OK) {
		zErr = "error in prepare";
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 1, num);
	if (rc != SQLITE_OK) {
		zErr = "error in bind";
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch(rc) {
	case SQLITE_DONE:
		addr = -1;
		break;
	case SQLITE_ROW:
		addr = sqlite3_column_int(stmt, 0);
		break;
	default:
		zErr = "error in step";
		break;
	}

out_finalize:
	if (zErr) fprintf(stderr, "DB_GetSizeForNum: %s\n", zErr);
	rc = sqlite3_finalize(stmt);
	if (rc != SQLITE_OK) fprintf(stderr,
		"DB_GetSizeForNum: error in finalize\n");
	return addr;
}

int DB_GetAddrForNum(sqlite3 *db, int num)
{
	__label__ out_finalize;
	char *zErr = NULL;
	int rc = SQLITE_OK;
	int addr = -1;

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(
		db,
		R"STATEMENT(
			select addr from frags where num==:num limit 1;
		)STATEMENT",
		-1,
		&stmt,
		NULL
	);
	if (rc != SQLITE_OK) {
		zErr = "error in prepare";
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 1, num);
	if (rc != SQLITE_OK) {
		zErr = "error in bind";
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch(rc) {
	case SQLITE_DONE:
		addr = -1;
		break;
	case SQLITE_ROW:
		addr = sqlite3_column_int(stmt, 0);
		break;
	default:
		zErr = "error in step";
		break;
	}

out_finalize:
	if (zErr) fprintf(stderr, "DB_GetAddrForNum: %s\n", zErr);
	rc = sqlite3_finalize(stmt);
	if (rc != SQLITE_OK) fprintf(stderr,
		"DB_GetAddrForNum: error in finalize\n");
	return addr;
}

int DB_FragSearch(sqlite3 *db, uint8_t *data, ssize_t size)
{
	int rc = SQLITE_OK;
	char pcode[6] = {0};
	get_pcode(pcode, data);
	DB_Begin(db);
	for (ssize_t i = 0; i < (size - 15); i += 16) {
		struct fragment_s *frag = (struct fragment_s *)(data + i);
		if (!isfrag(frag)) continue;
		rc = DB_AddFrag(
			db,
			pcode,
			i,
			get_frag_num(frag),
			get_ep(frag),
			ntohl(frag->code_offset),
			ntohl(frag->reloc_offset),
			ntohl(frag->romsize),
			ntohl(frag->memsize),
			get_segment(frag)
		);
		if (rc != SQLITE_OK) {
			break;
		}
	}
	DB_End(db);
	return rc;
}
