#ifndef _ELF_LIST_H_
#define _ELF_LIST_H_

#include "hok.h"
#include "elf_mmap.h"

//elf链表添加新节点,头插法，也就是说往前插入了一个，现在root指向插入的那个节点。
elf_list* add_elf(char* name, elf_list** root);

//删除一个节点
int remove_elf(elf_list** current);

elf_list** search_by_name(char* name, struct elf_list** current);
#endif // !_ELF_LIST_H_
