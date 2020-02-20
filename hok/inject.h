#ifndef _INJECT_H_
#define _INJECT_H_
#include "hok.h"

unsigned long inject_elf_binary(Elf32_mem_t* target, uint8_t* parasite, 
	int parasite_size, int jmp_code_offset, int method);

/* rewrite binary with text entry infection / TextEntryInfect*/
Elf32_Addr text_entry_infect(unsigned int psize, unsigned char* mem, char* parasite, int jmp_code_offset);

/* rewrite binary with text padding infection / TextPaddingInfect*/
Elf32_Addr text_padding_infect(unsigned int psize, unsigned char* mem,
	unsigned int end_of_text, char* parasite, int jmp_code_offset);
#endif // !_INJECT_H_
