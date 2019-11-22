#ifdef __MINGW32__
#include <winsock2.h>
#else
#define _GNU_SOURCE
#include <arpa/inet.h>
#endif
#include <ctype.h>
#include <inttypes.h>
#include <iso646.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db.h"
#include "fragment.h"
#include "mapfile.h"
#include "pcode.h"
#include "sqlite3.h"
#include "version.h"

sqlite3 *db;

char *cmd_mkdb(int argc, char **argv);
char *cmd_scan(int argc, char **argv);
char *cmd_depends(int argc, char **argv);
char *cmd_decompile(int argc, char **argv);
char *cmd_extract(int argc, char **argv);
char *cmd_extract_all(int argc, char **argv);

struct cmd_s {
	char *command;
	char *help;
	char *(*handler) (int argc, char **argv);
} cmds[] = {
	{
		.command = "scan",
		.help = "scan <rom>\n"
			"\t\tshow fragments within a rom",
		.handler = cmd_scan,
	},
	{
		.command = "depends",
		.help = "depends <rom> <fragnum>\n"
			"\t\tshow what fragments this one depends on",
		.handler = cmd_depends,
	},
	{
		.command = "extract",
		.help = "extract <rom> <fragnum>\n"
			"\t\textract one fragment",
		.handler = cmd_extract,
	},
	{
		.command = "extract-all",
		.help = "extract-all <rom>\n"
			"\t\textract all fragments",
		.handler = cmd_extract_all,
	},
	{
		.command = "mkdb",
		.help = "mkdb <rom> <sqlite3 database>\n"
			"\t\tpopulate an SQLite3 database with fragment data",
		.handler = cmd_mkdb,
	},
#ifndef __MINGW32__
	// this doesn't work on windows :(
	{
		.command = "decompile",
		.help = "decompile <rom> <fragnum>\n"
			"\t\tcreates .c file. requires avast's retdec",
		.handler = cmd_decompile,
	},
#endif
	{
		// end
		.command = NULL,
		.help = NULL,
		.handler = NULL,
	},
};

struct cmd_s *get_cmd_from_name(char *needle)
{
	int cmds_index = 0;
	while (cmds[cmds_index].command) {
		if (!strcmp(cmds[cmds_index].command, needle))
			return &cmds[cmds_index];
		cmds_index++;
	}
	return NULL;
}

void print_usage()
{
	fprintf(stderr, PROGRAM_NAME " version " VERSION_STRING
			", Copyright (C) 2019 jrra.\n"
			"A utility for code fragments in the Pokemon Stadium games.\n\n"
			"usage: " PROGRAM_NAME " <cmd>\n\n"
			"Commands:\n"
		);
	int cmds_index = 0;
	while (cmds[cmds_index].command) {
		fprintf(stderr, "\t%s\n", cmds[cmds_index].help);
		cmds_index++;
	}
	fprintf(stderr, "\nReport bugs to " URL_STRING "\n");
}

int dump_frags()
{
	__label__ out_return, out_finalize;
	int rc = SQLITE_OK;
	char *zErr = NULL;

	sqlite3_stmt *stmt;
	rc = sqlite3_prepare_v2(
		db,
		"select pcode,addr,num,entrypoint,offset_code,offset_relocs,romsize,ramsize,vma from frags order by num;",
		-1,
		&stmt,
		NULL
	);
	if (rc != SQLITE_OK) {
		zErr = "prepare";
		goto out_return;
	}

	printf("pcode,addr,num,entrypoint,offset_code,offset_relocs,romsize,ramsize,vma\n");

	while (SQLITE_DONE != (rc=sqlite3_step(stmt))) switch (rc) {
	case SQLITE_BUSY:
		break;
	case SQLITE_ERROR:
		zErr = "sqlite3_step returned SQLITE_ERROR";
		goto out_finalize;
		break;
	case SQLITE_MISUSE:
		zErr = "sqlite3_step returned SQLITE_MISUSE";
		goto out_finalize;
		break;
	default:
		zErr = "sqlite3_step returned some other error";
		goto out_finalize;
		break;
	case SQLITE_ROW:
		printf("%s,%" PRIuLEAST32 ",%" PRIuLEAST32 ",%" PRIuLEAST32 ",%" PRIuLEAST32 ",%" PRIuLEAST32 ",%" PRIuLEAST32 ",%" PRIuLEAST32 ",%" PRIuLEAST32 "\n",
			sqlite3_column_text(stmt, 0),
			(uint_least32_t)sqlite3_column_int64(stmt, 1),
			(uint_least32_t)sqlite3_column_int64(stmt, 2),
			(uint_least32_t)sqlite3_column_int64(stmt, 3),
			(uint_least32_t)sqlite3_column_int64(stmt, 4),
			(uint_least32_t)sqlite3_column_int64(stmt, 5),
			(uint_least32_t)sqlite3_column_int64(stmt, 6),
			(uint_least32_t)sqlite3_column_int64(stmt, 7),
			(uint_least32_t)sqlite3_column_int64(stmt, 8)
		);
		break;
	}

out_finalize:
	sqlite3_finalize(stmt);
out_return:
	if (zErr) {
		fprintf(stderr, "dump_frags: error: %s\n", zErr);
		return -1;
	} else
		return 0;
}

char *cmd_scan(int argc, char **argv)
{
	__label__ out_return;
	struct MappedFile_s m;
	char *msg = NULL;
	int rc;

	if (argc < 3) {
		msg = "must specify a pokemon stadium rom";
		goto out_return;
	}

	rc = DB_Init(&db, ":memory:");
	if (rc != SQLITE_OK) {
		msg = "DB_Init oopsed";
		goto out_return;
	}

	m = MappedFile_Open(argv[2], false);
	if (m.data == NULL) {
		msg = "couldn't open rom";
		goto out_dbclose;
	}

	if (m.size < (1048576 + 4096)) {
		msg = "rom too small";
		goto out_unmap;
	}

	rc = DB_FragSearch(db, m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	dump_frags();

out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close(db);
out_return:
	if (msg) {
		return msg;
	} else {
		return NULL;
	}
}

char *cmd_mkdb(int argc, char **argv)
{
	__label__ out_return, out_dbclose, out_unmap;
	struct MappedFile_s m;
	char *msg = NULL;
	int rc;

	switch (argc) {
	case 0 ... 2:
		msg = "must specify a Pokemon Stadium rom";
		goto out_return;
		break;
	case 3:
		msg = "must specify a database filename";
		goto out_return;
		break;
	default:
		break;
	}

	rc = DB_Init(&db, argv[3]);
	if (rc != SQLITE_OK) {
		msg = "DB_Init oopsed";
		goto out_return;
	}

	m = MappedFile_Open(argv[2], false);
	if (m.data == NULL) {
		msg = "couldn't open rom";
		goto out_dbclose;
	}

	if (m.size < (1048576 + 4096)) {
		msg = "rom too small";
		goto out_unmap;
	}

	rc = DB_FragSearch(db, m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	goto out_unmap;

out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close(db);
out_return:
	if (msg) {
		return msg;
	} else {
		return NULL;
	}

}

char *cmd_decompile(int argc, char **argv)
{
	__label__ out_return, out_dbclose, out_unmap;
	struct MappedFile_s m, outfile;
	int fragnum, fragaddr, fragsize, vma;
	char *msg = NULL, *outname = NULL, *command = NULL;
	char pcode[6];
	int rc;

	switch (argc) {
	case 0 ... 2:
		msg = "must specify a Pokemon Stadium rom";
		goto out_return;
		break;
	case 3:
		msg = "must specify a fragment number";
		goto out_return;
		break;
	default:
		break;
	}

	rc = DB_Init(&db, ":memory:");
	if (rc != SQLITE_OK) {
		msg = "DB_Init oopsed";
		goto out_return;
	}

	m = MappedFile_Open(argv[2], false);
	if (m.data == NULL) {
		msg = "couldn't open rom";
		goto out_dbclose;
	}

	if (m.size < (1048576 + 4096)) {
		msg = "rom too small";
		goto out_unmap;
	}

	rc = DB_FragSearch(db, m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	fragnum = atoi(argv[3]);
	fragaddr = DB_GetAddrForNum(db, fragnum);
	fragsize = DB_GetRomSizeForNum(db, fragnum);
	if (fragaddr == -1) {
		msg = "no fragment by that number";
		goto out_unmap;
	}

	get_pcode(pcode, m.data);
	rc = asprintf(&outname, "%s-frag%03d.bin", pcode, fragnum);
	outfile = MappedFile_Create(outname, fragsize);
	if (!outfile.data) {
		msg = "couldn't open outfile";
		goto out_unmap;
	}

	memcpy(outfile.data, m.data + fragaddr, fragsize);
	vma = get_vma(outfile.data);
	MappedFile_Close(outfile);

	asprintf(&command, "retdec-decompiler.py -k -a mips -e big -m raw --cleanup --backend-find-patterns all --backend-var-renamer simple --backend-no-debug-comments --raw-entry-point 0x%x --raw-section-vma 0x%x \"%s\"\n",
		vma,
		vma,
		outname
	);

	system(command);
	free(command);
	free(outname);
	goto out_unmap;


out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close(db);
out_return:
	if (msg) {
		return msg;
	} else {
		return NULL;
	}

}

char *cmd_depends(int argc, char **argv)
{
	__label__ out_return, out_dbclose, out_unmap, out_droptable;
	struct MappedFile_s m;
	char *msg = NULL;
	int rc;
	int fragnum;
	char pcode[6];

	switch (argc) {
	case 0 ... 2:
		msg = "must specify a Pokemon Stadium rom";
		goto out_return;
		break;
	case 3:
		msg = "must specify a fragment number";
		goto out_return;
		break;
	default:
		break;
	}

	rc = DB_Init(&db, ":memory:");
	if (rc != SQLITE_OK) {
		msg = "DB_Init oopsed";
		goto out_return;
	}

	m = MappedFile_Open(argv[2], false);
	if (m.data == NULL) {
		msg = "couldn't open rom";
		goto out_dbclose;
	}

	if (m.size < (1048576 + 4096)) {
		msg = "rom too small";
		goto out_unmap;
	}

	get_pcode(pcode, m.data);

	rc = DB_FragSearch(db, m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	fragnum = atoi(argv[3]);
	int fragaddr = DB_GetAddrForNum(db, fragnum);
	if (fragaddr == -1) {
		msg = "no fragment by that number";
		goto out_unmap;
	}
	//parse_relocs(m.data + fragaddr);
	uint32_t *fragbytes = m.data + fragaddr;

	// start

	rc = sqlite3_exec(
		db,
		"create temp table relocs(reloc_id integer primary key, pcode, fragnum, far, type, addr, target_addr, target_frag);",
		NULL, NULL, NULL
	);
	if (rc != SQLITE_OK) {
		msg = "create temp table failed";
		goto out_unmap;
	};

	sqlite3_stmt *stmt = NULL;
	rc = sqlite3_prepare_v2(
		db,
		"insert into temp.relocs(pcode, fragnum, far, type, addr, target_addr, target_frag) values (?, ?, ?, ?, ?, ?, ?);",
		-1,
		&stmt,
		NULL
	);
	if (rc != SQLITE_OK) {
		msg = "prepare";
		goto out_droptable;
	}

	rc = DB_Begin(db);
	if (rc != SQLITE_OK) {
		msg = "begin transaction";
		goto out_droptable;
	}
	struct fragment_s frag;
	memcpy(&frag, fragbytes, sizeof(struct fragment_s));
	uint32_t *words = (uint32_t *)fragbytes;
	uint32_t *reloc_words = words;
	reloc_words += htonl(frag.offset_relocs) / sizeof(uint32_t);
	uint32_t num_relocs = htonl(reloc_words[0]);
	reloc_words++;
	printf("%d relocations.\n", num_relocs);
	for(int i = 0; i<num_relocs; i++) {
		uint32_t reloc = htonl(reloc_words[i]);
		bool foreign = reloc & 0x80000000;
		uint32_t type = reloc & 0x7F000000;
		uint32_t addr = reloc & 0x00FFFFFF;
		uint32_t target = htonl(words[addr>>2]);
		uint32_t loc = -1;
		uint32_t n;
		int loc_fragnum = -2;

		char *zType = NULL;

		switch (type) {
		case 0x02000000:
			zType = "ptr";
			loc = target;
			break;
		case 0x04000000:
			zType = "j";
			loc = (target & 0x03FFFFFF) << 2;
			loc |= 0x80000000;
			break;
		case 0x05000000:
			zType = "lui";
			loc = (target & 0x0000FFFF) << 16;
			loc |= 0x80000000;
			break;
		case 0x06000000:
			zType = "addiu";
			loc = (target & 0x0000FFFF);
			if (!foreign)
				loc += get_vma(&frag);
			break;
		default:
			zType = "unknown";
			loc = -1;
			break;
		}

		n = (loc & 0x0FF00000)>>20;
		loc_fragnum = n - 16;
// 		printf("%5d %08x %8x %08x\t%s\t%d\n",
// 			i,
// 			reloc,
// 			addr,
// 			loc,
// 			zType,
// 			loc_fragnum
// 		);
		if (loc_fragnum < 0) continue;
// "insert into temp.relocs(pcode, fragnum, far, type, addr, target_addr, target_frag) values (?, ?, ?, ?, ?, ?, ?);"
		rc = sqlite3_bind_text(stmt, 1, pcode, -1, SQLITE_TRANSIENT);
		if (rc != SQLITE_OK) {msg = "bind 1";}
		rc = sqlite3_bind_int64(stmt, 2, fragnum);
		if (rc != SQLITE_OK) {msg = "bind 2";}
		rc = sqlite3_bind_int64(stmt, 3, foreign);
		if (rc != SQLITE_OK) {msg = "bind 3";}
		rc = sqlite3_bind_text(stmt, 4, zType, -1, SQLITE_STATIC);
		if (rc != SQLITE_OK) {msg = "bind 4";}
		rc = sqlite3_bind_int64(stmt, 5, addr);
		if (rc != SQLITE_OK) {msg = "bind 5";}
		rc = sqlite3_bind_int64(stmt, 6, loc);
		if (rc != SQLITE_OK) {msg = "bind 6";}
		rc = sqlite3_bind_int64(stmt, 7, loc_fragnum);
		if (rc != SQLITE_OK) {msg = "bind 7";}

		rc = sqlite3_step(stmt);
		if (rc != SQLITE_DONE) {msg = "step";}

		rc = sqlite3_reset(stmt);
		if (rc != SQLITE_OK) {msg = "reset";}
	}

	DB_End(db);

	rc = sqlite3_finalize(stmt);
	if (rc != SQLITE_OK) {msg = "finalize1"; goto out_droptable;}

	rc = sqlite3_prepare(
		db,
		"select distinct target_frag from temp.relocs where target_frag != fragnum order by target_frag;",
		-1,
		&stmt,
		NULL
	);
	if (rc != SQLITE_OK) { msg = "prepare2"; goto out_droptable;}

	bool did_print_first = false;
	while (SQLITE_DONE != (rc=sqlite3_step(stmt))) switch (rc) {
	case SQLITE_BUSY:
		break;
	case SQLITE_ERROR:
		msg = "sqlite3_step returned SQLITE_ERROR";
		goto out_finalize;
		break;
	case SQLITE_MISUSE:
		msg = "sqlite3_step returned SQLITE_MISUSE";
		goto out_finalize;
		break;
	default:
		msg = "sqlite3_step returned some other error";
		goto out_finalize;
		break;
	case SQLITE_ROW:
		printf("%s%d", did_print_first?", ":"Depends on ",sqlite3_column_int(stmt, 0));
		did_print_first = true;
		break;
	}

	if (did_print_first) {
		printf(".\n");
	} else {
		printf("No dependencies.\n");
	}

out_finalize:
	rc = sqlite3_finalize(stmt);
	if (!msg)
		if (rc != SQLITE_OK) {msg = "finalize2"; goto out_droptable;}
out_droptable:
	rc = sqlite3_exec(
		db,
		"drop table temp.relocs;",
		NULL, NULL, NULL
	);
out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close(db);
out_return:
	if (msg) {
		return msg;
	} else {
		return NULL;
	}

}

char *_cmd_extract_aux(int argc, char **argv, bool all)
{
	__label__ out_return, out_dbclose, out_unmap, out_finalize;
	char *msg = NULL;
	int rc;
	struct MappedFile_s m, outfile;
	int num, addr, size;
	char *outname = NULL;
	char pcode[6];

	switch (argc) {
	case 0 ... 2:
		msg = "must specify a Pokemon Stadium rom";
		goto out_return;
		break;
	case 3:
		if (!all) {
			msg = "must specify a fragment number";
			goto out_return;
		}
		break;
	default:
		break;
	}

	rc = DB_Init(&db, ":memory:");
	if (rc != SQLITE_OK) {
		msg = "DB_Init oopsed";
		goto out_return;
	}

	m = MappedFile_Open(argv[2], false);
	if (m.data == NULL) {
		msg = "couldn't open rom";
		goto out_dbclose;
	}

	if (m.size < (1048576 + 4096)) {
		msg = "rom too small";
		goto out_unmap;
	}

	get_pcode(pcode, m.data);
	rc = DB_FragSearch(db, m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	sqlite3_stmt *stmt = NULL;
	if (all) {
		rc = sqlite3_prepare_v2(
			db,
			"select num,addr,romsize from frags order by num;",
			-1, &stmt, NULL
		);
		if (rc != SQLITE_OK) {
			msg = "error in prepare (all)";
			goto out_finalize;
		}
	} else {
		num = atoi(argv[3]);
		rc = sqlite3_prepare_v2(
			db,
			"select num,addr,romsize from frags where num=?;",
			-1, &stmt, NULL
		);
		if (rc != SQLITE_OK) {
			msg = "error in prepare (one)";
			goto out_finalize;
		}
		rc = sqlite3_bind_int(stmt, 1, num);
		if (rc != SQLITE_OK) {
			msg = "error in bind";
			goto out_finalize;
		}
	}

	if (!all and (DB_GetAddrForNum(db, num) == -1)) {
		msg = "no fragment by that number";
		goto out_finalize;
	}

	while (SQLITE_DONE != (rc=sqlite3_step(stmt))) switch (rc) {
	case SQLITE_BUSY:
		break;
	case SQLITE_ERROR:
		msg = "sqlite3_step returned SQLITE_ERROR";
		goto out_finalize;
		break;
	case SQLITE_MISUSE:
		msg = "sqlite3_step returned SQLITE_MISUSE";
		goto out_finalize;
		break;
	default:
		msg = "sqlite3_step returned some other error";
		goto out_finalize;
		break;
	case SQLITE_ROW:
		num  = sqlite3_column_int(stmt, 0);
		addr = sqlite3_column_int(stmt, 1);
		size = sqlite3_column_int(stmt, 2);
		rc = asprintf(&outname, "%s-frag%03d.bin", pcode, num);
		if (rc == -1) {
			msg = "asprintf failed";
			goto out_finalize;
		}
		outfile = MappedFile_Create(outname, size);
		if (!outfile.data) {
			free(outname);
			msg = "couldn't open outfile";
			goto out_finalize;
		}
		memcpy(outfile.data, m.data + addr, size);
		free(outname);
		MappedFile_Close(outfile);
		break;
	}


out_finalize:
	sqlite3_finalize(stmt);
out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close(db);
out_return:
	if (msg) {
		return msg;
	} else {
		return NULL;
	}

}

char *cmd_extract(int argc, char **argv)
{
	return _cmd_extract_aux(argc, argv, false);
}

char *cmd_extract_all(int argc, char **argv)
{
	return _cmd_extract_aux(argc, argv, true);
}
/*
	continue;
	char *filename;
	int rc;
	rc = asprintf(&filename, "fragment%03d.bin", get_frag_num(frag));
	if (rc < 0) goto err_oom;
	struct MappedFile_s f = MappedFile_Create(
		filename, ntohl(frag->romsize));
	free(filename);
	if (!f.data) {
		MappedFile_Close(f);
		goto err_outfile;
	}
	memcpy(f.data, m.data+i, ntohl(frag->romsize));
	MappedFile_Close(f);
}
*/

int main(int argc, char **argv)
{
	__label__ out_return;
	char *msg = NULL;
	char *cmd_string = NULL;

	if (argc < 2) {
		print_usage();
		goto out_return;
	}

	cmd_string = argv[1];

	struct cmd_s *cmd = get_cmd_from_name(cmd_string);
	if (cmd != NULL) {
		if (cmd->handler)
			msg = cmd->handler(argc, argv);
		else
			msg = "command has no handler";
	} else {
		msg = "invalid command";
	}

out_return:
	if (msg) {
		fprintf(stderr, "%s: error: %s\n", argv[0], msg);
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}
