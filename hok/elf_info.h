#ifndef _ELF_INFO_H_
#define _ELF_INFO_H_

#include "hok.h"

linking_info* get_plt(unsigned char* mem);

Elf32_Addr get_base(Elf32_mem_t* target, int witch);

//向目标elf文件添加新符号
int add_symbol(char* name, Elf32_Addr vaddr, Elf32_Sym* sym, Elf32_mem_t* target);

Elf32_Sym* get_sym_by_name(char* name, Elf32_Shdr* shdr, int c, uint8_t* objmem);

Elf32_Addr get_reloc_sym_addr(char* name, Elf32_Shdr* shdr, int c, uint8_t* objmem);
#endif // !_ELF_INFO_H_
