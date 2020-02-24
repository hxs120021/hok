#ifndef _ELF_MMAP_H_
#define _ELF_MMAP_H_

#include "hok.h"
#include "cmd.h"

//判断是否为ELF文件
int is_elf(uint8_t* mem);

//加载elf，按照name将指定的elf文件按照 Elf32_mem_t格式加载到 &elf中，protect:保护 flag：标志， offset：偏移 v_addr:虚拟地址
int load_elf(char* name, int flags, int protect, Elf32_Addr v_addr, Elf32_Off offset, Elf32_mem_t *elf);

//构建节头
int build_sections(uint8_t*** section, uint8_t* mem);

//卸载elf
int unload_elf(Elf32_mem_t* elf);

//暂时还不知道干什么用的函数：
int reload_elf(Elf32_mem_t* elf);

//我们使用 msync 提交不需要文件大小扩展名的更改
int commit_changes(Elf32_mem_t* target);
#endif