#include "elf_mmap.h"

int is_elf(uint8_t* mem) {
	Elf32_Ehdr* ehdr = (Elf32_Ehdr*)mem;

	if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF")) {
		printf("FIle is missing ELF magic\n");
		return FILE_ERR;
	}

	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN && ehdr->e_type != ET_REL
		&& ehdr->e_type != ET_CORE && ehdr->e_type != ET_NONE) {
		printf("File is not any of the following ELF types: EXEC, DYN, REL, CORE, NONE\n");
		return FILE_ERR;
	}

	if (ehdr->e_machine != EM_386 && ehdr->e_machine != EM_860) {
		printf("File is not any of the following machine types: i386, 860\n");
		return FILE_ERR;
	}
	return SUCCESS;
}

int load_elf(char* name, int flags, int protect, Elf32_Addr v_addr, Elf32_Off offset, Elf32_mem_t* elf) {
	int fd;
	uint8_t* mem;
	STAT st;
	
	strncpy(elf->name, name, MAXSTR - 1);
	if ((fd = open(name, O_RDWR)) == -1) {
		perror("load_elf() open\n");
		return OPFILE_ERR;
	}

	if (fstat(fd, &st) < 0) {
		perror("load_elf() fstat\n");
		return FILE_ERR;
	}

	mem = mmap((void*)NULL, st.st_size, protect, flags, fd, offset);
	if (mem == MAP_FAILED) {
		perror("load_elf() mmap\n");
		return SYS_ERR;
	}

	if (!is_elf(mem))
		return FILE_ERR;
		
	elf->size = st.st_size;
	elf->mode = st.st_mode;
	elf->mem = mem;
	elf->ehdr = (Elf32_Ehdr*)mem;
	elf->shdr = (Elf32_Shdr*)(elf->ehdr->e_shoff + mem);
	elf->phdr = (Elf32_Phdr*)(elf->ehdr->e_phoff + mem);
	elf->elf_type = elf->ehdr->e_type;

	//定义PT_LOAD虚拟地址和偏移,大一上就是text段与存放全局变量和动态链接信息的data段
	for (int i = 0; i < elf->ehdr->e_phnum; i++) {
		if (elf->phdr[i].p_offset == 0 || elf->phdr[i].p_offset == 0x1000) {
			//PF_X是判断flag表示可执行
			if (elf->phdr[i].p_type == PT_LOAD && (elf->phdr[i].p_flags & PF_X)) {
				elf->text_vaddr = elf->phdr[i].p_vaddr;
				elf->text_offset = elf->phdr[i].p_offset;
				elf->text_filesz = elf->phdr[i].p_filesz;
				elf->text_memsz = elf->phdr[i].p_memsz;

				if (elf->phdr[i + 1].p_type == PT_LOAD) {
					int j = i + 1;
					elf->data_vaddr = elf->phdr[j].p_vaddr;
					elf->data_offset = elf->phdr[j].p_offset;
					elf->data_filesz = elf->phdr[j].p_filesz;
					elf->data_memsz = elf->phdr[j].p_memsz;
				}
				break;
			}
		}
	}

	elf->typestr[0] = strdup("ET_NONE");
	elf->typestr[1] = strdup("ET_REL");
	elf->typestr[2] = strdup("ET_EXEC");
	elf->typestr[3] = strdup("ET_DYN");
	elf->typestr[4] = strdup("ET_CORE");
	build_sections(&elf->section, mem);
	close(fd);
	return SUCCESS;
}

int build_sections(uint8_t*** section, uint8_t* mem) {
	Elf32_Ehdr* ehdr = (Elf32_Addr*)mem;
	Elf32_Shdr* shdr = (Elf32_Shdr*)(ehdr->e_shoff + mem);

	if ((*section = (uint8_t**)calloc(ehdr->e_shnum, sizeof(uint8_t*))) == NULL) {
		printf("build_sections() calloc error\n");
		return MEM_ERR;
	}

	for (int i = 0; i < ehdr->e_shnum; i++, shdr++) {
		//把每个节的节头都单独拿出来按照内存复制给section
		if ((*((*section) + i) = malloc(shdr->sh_size)) == NULL) {
			printf("build_sections() malloc error\n");
			return MEM_ERR;
		}
		memcpy(*((*section) + i), &mem[shdr->sh_offset], shdr->sh_size);
	}

	return SUCCESS;
}

int unload_elf(Elf32_mem_t* elf) {
	if (!elf)
		return NULL_ERR;
	if (munmap(elf->mem, elf->size) < 0)
		return MEM_ERR;
	return SUCCESS;
}