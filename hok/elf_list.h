#ifndef _ELF_LIST_H_
#define _ELF_LIST_H_

#include "hok.h"

//elf链表添加新节点,头插法，也就是说往前插入了一个，现在root指向插入的那个节点。
int add_elf(char* name, elf_list** root);

#endif // !_ELF_LIST_H_
