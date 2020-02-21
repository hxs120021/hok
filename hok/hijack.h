#ifndef _HIJACK_H_
#define _HIJACK_H

#include "hok.h"
#include "elf_list.h"
#include "cmd.h"
#include "elf_info.h"

int hijack(char** args, int args_len, elf_list** current, elf_list*** list_head);

int hijack_function(Elf32_mem_t* target, int mode, unsigned long new_vaddr, char* function);
#endif // !_HIJACK_H_