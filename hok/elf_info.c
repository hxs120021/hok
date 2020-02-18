#include "elf_info.h"

linking_info* get_plt(unsigned char* mem) {
	Elf32_Ehdr* ehdr;
	Elf32_Shdr* shdr, * shdrp, * symshdr;
	Elf32_Sym* syms, * symsp;
	Elf32_Rel* rel;

	char* symbol;
	int sym_count;
	linking_info* link;
	ehdr = (Elf32_Ehdr*)mem;
	shdr = (Elf32_Shdr*)(ehdr->e_shoff + mem);
	//定位指针，定位起始地址
	shdrp = shdr;
	//这个地方原文为什么倒着来？
	//for(int i = ehdr->e_shnum; i-- > 0; shdrp++){
	for (int i = 1; i < ehdr->e_shnum; shdrp++) {
		if (shdrp->sh_type == SHT_DYNSYM) {
			//.dynsym节，保存了动态符号信息，下面就是找到链接的符号表所在的节
			symshdr = &shdr[shdrp->sh_link];
			if ((symbol = malloc(symshdr->sh_size)) == NULL) {
				printf("get_plt() malloc() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
				return MEM_ERR;
			}
			//从该节起始地址开始向symbol指向地址中开始复制，大小为该节sh_size
			memcpy(symbol, (symshdr->sh_offset + mem), symshdr->sh_size);
			//获取当前节即.dynsym节的内容，即整个符号表内容，并复制到syms中
			if ((syms = (Elf32_Sym*)malloc(shdrp->sh_size)) == NULL) {
				printf("get_plt() malloc() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
				return MEM_ERR;
			}
			memcpy(syms, (shdrp->sh_offset + mem), shdrp->sh_size);
			
			//定位指针，定位符号表第一个表项
			symsp = syms;
			//计算符号表项有多少个
			sym_count = shdrp->sh_size / sizeof(Elf32_Sym);
			if ((link = (linking_info*)malloc(sizeof(linking_info) * sym_count)) == NULL) {
				printf("get_plt() malloc() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
				return MEM_ERR;
			}
			link[0].count = sym_count;
			
			for (int j = 0; j < sym_count; j++, symsp++) {
				//把每个表项的名字复制到link.name中，符号来源于符号表，使用当前表项的st_name索引
				strncpy(link[j].name, &symbol[symsp->st_name], sizeof(link[j].name) - 1);
				if (!link[j].name) {
					printf("get_plt() strncpy() file:%s, line:%d\n", __FILE__, __LINE__ - 2);
					return MEM_ERR;
				}
				link[j].s_value = symsp->st_value;
				link[j].index = j;
			}
			break;
		}
	}

	for (int i = ehdr->e_shnum; i-- > 0; shdr++) {
		switch (shdr->sh_type) {
		case SHT_REL:
			rel = (Elf32_Rel*)(shdr->sh_offset + mem);
			//因为用的是size，所以需要一块一块的跳，不能一个一个的执行了
			for (int j = 0; j < shdr->sh_size; j += sizeof(Elf32_Rel), rel++) {
				//外循环遍历重定位表所有表项，
				for (int k = 0; k < sym_count; k++) {
					//内循环是为了找到在link[].index和当前外循环的节能对起来，说明表项的偏移等信息是对的。
					if (ELF32_R_SYM(rel->r_info) == link[k].index) {
						link[k].r_offset = rel->r_offset;
						link[k].r_info = rel->r_info;
						link[k].r_type = ELF32_R_TYPE(rel->r_info);
						//原文没有这个break
						break;
					}
				}
			}
			break;
		case SHT_RELA:
			break;
		default:
			break;
		}
	}

	return link;
}