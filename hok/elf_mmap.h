#ifndef _ELF_MMAP_H_
#define _ELF_MMAP_H_

#include "hok.h"
#include "cmd.h"

//�ж��Ƿ�ΪELF�ļ�
int is_elf(uint8_t* mem);

//����elf������name��ָ����elf�ļ����� Elf32_mem_t��ʽ���ص� &elf�У�protect:���� flag����־�� offset��ƫ�� v_addr:�����ַ
int load_elf(char* name, int flags, int protect, Elf32_Addr v_addr, Elf32_Off offset, Elf32_mem_t *elf);

//������ͷ
int build_sections(uint8_t*** section, uint8_t* mem);

//ж��elf
int unload_elf(Elf32_mem_t* elf);

//��ʱ����֪����ʲô�õĺ�����
int reload_elf(Elf32_mem_t* elf);

//����ʹ�� msync �ύ����Ҫ�ļ���С��չ���ĸ���
int commit_changes(Elf32_mem_t* target);
#endif