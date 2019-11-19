#include <arpa/inet.h>
#include "fragment.h"
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