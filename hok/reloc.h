#ifndef _RELOC_H_
#define _RELOC_H_

#include "hok.h"
#include "elf_list.h"
#include "elf_mmap.h"
#include "inject.h"
#include "elf_info.h"

//relocÃüÁî ´¦Àíº¯Êı
int reloc(char** args, int args_len, elf_list** current, elf_list*** list_head);

//
int elf_relocate(Elf32_mem_t* target, char* name, int type);


#endif