#ifdef __MINGW32__
#include <winsock.h>
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
#include <sqlite3.h>
#include "db.h"
#include "fragment.h"
#include "mapfile.h"
#include "pcode.h"
#include "version.h"

sqlite3 *db;

char *cmd_mkdb(int argc, char **argv);
char *cmd_scan(int argc, char **argv);
char *cmd_relocs(int argc, char **argv);
char *cmd_decompile(int argc, char **argv);

struct cmd_s {
	char *command;
	char *help;
	char *(*handler) (int argc, char **argv);
} cmds[] = {
	{
		.command = "mkdb",
		.help = "mkdb <rom> <sqlite3 database>\n"
			"\t\tpopulate an SQLite3 database with fragment data",
		.handler = cmd_mkdb,
	},
	{
		.command = "scan",
		.help = "scan <rom>\n"
			"\t\tshow fragments within a rom",
		.handler = cmd_scan,
	},
	{
		.command = "relocs",
		.help = "relocs <rom> <fragnum>\n"
			"\t\tdump relocations of a fragment",
		.handler = cmd_relocs,
	},
	{
		.command = "decompile",
		.help = "decompile <rom> <fragnum>\n"
			"\t\tcreates .c file\n",
		.handler = cmd_decompile,
	},
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
	fprintf(stderr, "fragtool version " VERSION_STRING
			", Copyright (C) 2019 jrra.\n"
			"A utility for code fragments in the Pokemon Stadium games.\n\n"
			"usage: fragtool <cmd>\n\n"
			"Commands:\n"
		);
	int cmds_index = 0;
	while (cmds[cmds_index].command) {
		fprintf(stderr, "\t%s\n", cmds[cmds_index].help);
		cmds_index++;
	}
	fprintf(stderr, "\nReport bugs to " URL_STRING "\n");
}

void parse_relocs(uint8_t *fragbytes)
{
	struct fragment_s frag;
	memcpy(&frag, fragbytes, sizeof(struct fragment_s));
	uint32_t *words = (uint32_t *)fragbytes;
	uint32_t *reloc_words = words;
	reloc_words += htonl(frag.reloc_offset) / sizeof(uint32_t);
	uint32_t num_relocs = htonl(reloc_words[0]);
	reloc_words++;
	printf("%d relocations\n", num_relocs);
	for(int i = 0; i<num_relocs; i++) {
		uint32_t reloc = htonl(reloc_words[i]);
		bool foreign = reloc & 0x80000000;
		uint32_t type = reloc & 0x7F000000;
		uint32_t addr = reloc & 0x00FFFFFF;
		uint32_t target = htonl(words[addr>>2]);
		uint32_t loc = -1;
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
				loc += get_segment(&frag);
			break;
		default:
			zType = "unknown";
			loc = -1;
			break;
		}

		switch ((loc & 0x0FF00000)>>20) {
		case 0:
			loc_fragnum = -1; break;
		case 1 ... 15:
			loc_fragnum = -999; break;
		default:
			loc_fragnum = ((loc & 0x0FF00000)>>20)-16;
			break;
		}
		printf("%5d %08x %8x %08x\t%s\t%d\n",
			i,
			reloc,
			addr,
			loc,
			zType,
			loc_fragnum
		);
	}
}

int dump_frags()
{
	__label__ out_return, out_finalize;
	int rc = SQLITE_OK;
	char *zErr = NULL;

	sqlite3_stmt *stmt;
	rc = sqlite3_prepare_v2(
		db,
		"select pcode,addr,num,ep,code,reloc,size,memsize,segment from frags order by num;",
		-1,
		&stmt,
		NULL
	);
	if (rc != SQLITE_OK) {
		zErr = "prepare";
		goto out_return;
	}

	printf("pcode,addr,num,ep,code,reloc,size,memsize,segment\n");

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
		printf("%s,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld\n",
			sqlite3_column_text(stmt, 0),
			sqlite3_column_int64(stmt, 1),
			sqlite3_column_int64(stmt, 2),
			sqlite3_column_int64(stmt, 3),
			sqlite3_column_int64(stmt, 4),
			sqlite3_column_int64(stmt, 5),
			sqlite3_column_int64(stmt, 6),
			sqlite3_column_int64(stmt, 7),
			sqlite3_column_int64(stmt, 8)
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
	fragsize = DB_GetSizeForNum(db, fragnum);
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

char *cmd_relocs(int argc, char **argv)
{
	__label__ out_return;
	struct MappedFile_s m;
	char *msg = NULL;
	int rc;

	if (argc < 3) {
		msg = "must specify a pokemon stadium rom";
		goto out_return;
	}
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

	int fragaddr = DB_GetAddrForNum(db, atoi(argv[3]));
	if (fragaddr == -1) {
		msg = "no fragment by that number";
		goto out_unmap;
	}
	parse_relocs(m.data + fragaddr);

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
