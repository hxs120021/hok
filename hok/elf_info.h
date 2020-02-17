#ifndef _ELF_INFO_H_
#define _ELF_INFO_H_

#include "hok.h"

linking_info* get_plt(unsigned char* mem);

Elf32_Addr get_base(Elf32_mem_t* target, int witch);

#endif // !_ELF_INFO_H_
