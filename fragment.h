#ifndef _FRAGMENT_H_
#define _FRAGMENT_H_
#include <inttypes.h>
#include <stdbool.h>

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

int32_t get_frag_num(struct fragment_s *frag);
uint32_t get_vma(struct fragment_s *frag);
uint32_t get_ep_offset(struct fragment_s *frag);
uint32_t get_ep(struct fragment_s *frag);
uint32_t get_segment(struct fragment_s *frag);
bool isfrag(struct fragment_s *frag);
#endif
