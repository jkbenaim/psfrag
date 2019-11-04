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
#include "mapfile.h"
#include "version.h"

sqlite3 *db;

struct fragment_s {
	uint32_t ep1;		// j xxxx
	uint32_t ep2;		// nop
	uint32_t magic1;	// "FRAG"
	uint32_t magic2;	// "MENT"
	uint32_t code_offset;
	uint32_t reloc_offset;
	uint32_t romsize;
	uint32_t memsize;
	char data[];
} __attribute__(( packed ));

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

int DB_Init(char *filename) {
	int rc = SQLITE_OK;
	rc = sqlite3_open(filename, &db);
	if (rc != SQLITE_OK) return rc;

	rc = sqlite3_exec(db,
		"CREATE TABLE IF NOT EXISTS frags(pcode text, addr int, num int, ep int, code int, reloc int, size int, memsize int, segment int);",
		NULL, NULL, NULL
	);
	if (rc != SQLITE_OK) return rc;
	return SQLITE_OK;
}

int DB_Close() {
	int rc = SQLITE_OK;
	rc = sqlite3_close(db);
	return rc;
}

int DB_Begin() {
	return sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
}

int DB_End() {
	return sqlite3_exec(db, "END;", NULL, NULL, NULL);
}

int DB_AddFrag(
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

int DB_GetSizeForNum(int num)
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

int DB_GetAddrForNum(int num)
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

char *get_pcode(char pcode[6], uint8_t *rom)
{
	__label__ out;
	if (!rom or !pcode) goto out;
	pcode[0] = rom[0x3b];
	pcode[1] = rom[0x3c];
	pcode[2] = rom[0x3d];
	pcode[3] = rom[0x3e];
	pcode[4] = rom[0x3f] + '0';
	pcode[5] = '\0';
	for (int i=0; i < 4; i++) {
		if (!isalnum(pcode[i]))
			pcode[i] = '_';
		else
			pcode[i] = tolower(pcode[i]);
	}

	if (!isdigit(pcode[4]))
		pcode[4] = '_';

out:
	return pcode;
}

int32_t get_frag_num(struct fragment_s *frag)
{
	uint32_t ep1 = ntohl(frag->ep1);
	unsigned opcode = (ep1 & 0xfc000000) >> (32-6);
	uint32_t address = (ep1 & 0x03ffffff) << 2;
	if (opcode != 2) return -1;
	int fragnum = ((address >> 20) & 0xff) - 0x10;
	return fragnum;
}

uint32_t get_vma(struct fragment_s *frag)
{
	uint32_t ep1, address, vma;
	ep1 = ntohl(frag->ep1);
	address = (ep1 & 0x03ffffff) << 2;
	address |= 0x80000000;
	vma = address & 0xFFF00000;
	return vma;
}

uint32_t get_ep_offset(struct fragment_s *frag)
{
	uint32_t ep1 = ntohl(frag->ep1);
	uint32_t address = (ep1 & 0x03ffffff) << 2;
	address &= 0x000fffff;
	return address;
}

uint32_t get_ep(struct fragment_s *frag)
{
	uint32_t ep1 = ntohl(frag->ep1);
	uint32_t address = (ep1 & 0x03ffffff) << 2;
	address |= 0x80000000;
	return address;
}

uint32_t get_segment(struct fragment_s *frag)
{
	return get_ep(frag) & 0xFFF00000;
}

bool isfrag(struct fragment_s *frag)
{
	if (ntohl(frag->magic1) != 0x46524147) return false;
	if (ntohl(frag->magic2) != 0x4d454e54) return false;
	return true;
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

int DB_FragSearch(uint8_t *data, ssize_t size)
{
	int rc = SQLITE_OK;
	char pcode[6] = {0};
	get_pcode(pcode, data);
	DB_Begin();
	for (ssize_t i = 0; i < (size - 15); i += 16) {
		struct fragment_s *frag = (struct fragment_s *)(data + i);
		if (!isfrag(frag)) continue;
		rc = DB_AddFrag(
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
	DB_End();
	return rc;
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

	rc = DB_Init(":memory:");
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

	rc = DB_FragSearch(m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	dump_frags();

out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close();
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

	rc = DB_Init(argv[3]);
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

	rc = DB_FragSearch(m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	goto out_unmap;

out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close();
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

	rc = DB_Init(":memory:");
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

	rc = DB_FragSearch(m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	fragnum = atoi(argv[3]);
	fragaddr = DB_GetAddrForNum(fragnum);
	fragsize = DB_GetSizeForNum(fragnum);
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
	DB_Close();
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

	rc = DB_Init(":memory:");
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

	rc = DB_FragSearch(m.data, m.size);
	if (rc != SQLITE_OK) {
		msg = "DB_FragSearch oopsed";
		goto out_unmap;
	}

	int fragaddr = DB_GetAddrForNum(atoi(argv[3]));
	if (fragaddr == -1) {
		msg = "no fragment by that number";
		goto out_unmap;
	}
	parse_relocs(m.data + fragaddr);

out_unmap:
	MappedFile_Close(m);
out_dbclose:
	DB_Close();
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
