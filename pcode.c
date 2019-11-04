#include <ctype.h>
#include "pcode.h"
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
