#include "inject.h"

char* host;

unsigned long inject_elf_binary(Elf32_mem_t* target, uint8_t* parasite,
	int parasite_size, int jmp_code_offset, int method) {
	int fd, text_found = 0;
	//文件属性位掩码的类型。
	mode_t mode;

	uint8_t* mem = target->mem;
	host = target->name;
}