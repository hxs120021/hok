#ifndef _INJECT_H_
#define _INJECT_H_
#include "hok.h"

unsigned long inject_elf_binary(Elf32_mem_t* target, uint8_t* parasite, 
	int parasite_size, int jmp_code_offset, int method);
#endif // !_INJECT_H_
