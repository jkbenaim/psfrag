#ifndef _FRAGMENT_H_
#define _FRAGMENT_H_
#include <inttypes.h>
#include <stdbool.h>

struct fragment_s {
	uint32_t entrypoint1;	// j xxxx
	uint32_t entrypoint2;	// nop
	uint32_t magic1;	// "FRAG"
	uint32_t magic2;	// "MENT"
	uint32_t offset_code;
	uint32_t offset_relocs;
	uint32_t romsize;
	uint32_t ramsize;
	char data[];
} __attribute__(( packed ));

int32_t get_frag_num(struct fragment_s *frag);
uint32_t get_vma(struct fragment_s *frag);
uint32_t get_entrypoint_offset(struct fragment_s *frag);
uint32_t get_entrypoint(struct fragment_s *frag);
bool isfrag(struct fragment_s *frag);
#endif
