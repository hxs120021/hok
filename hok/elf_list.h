#ifndef _ELF_LIST_H_
#define _ELF_LIST_H_

#include "hok.h"
#include "elf_mmap.h"

//elf��������½ڵ�,ͷ�巨��Ҳ����˵��ǰ������һ��������rootָ�������Ǹ��ڵ㡣
elf_list* add_elf(char* name, elf_list** root);

//ɾ��һ���ڵ�
int remove_elf(elf_list** current);

elf_list** search_by_name(char* name, struct elf_list** current);
#endif // !_ELF_LIST_H_
