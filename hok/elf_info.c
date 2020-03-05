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
	//��λָ�룬��λ��ʼ��ַ
	shdrp = shdr;
	//����ط�ԭ��Ϊʲô��������
	//for(int i = ehdr->e_shnum; i-- > 0; shdrp++){
	for (int i = ehdr->e_shnum; i-- > 0; shdrp++) {
		if (shdrp->sh_type == SHT_DYNSYM) {
			//.dynsym�ڣ������˶�̬������Ϣ����������ҵ����ӵķ��ű����ڵĽ�
			symshdr = &shdr[shdrp->sh_link];
			if ((symbol = malloc(symshdr->sh_size)) == NULL) {
				printf("get_plt() malloc() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
				return MEM_ERR;
			}
			//�Ӹý���ʼ��ַ��ʼ��symbolָ���ַ�п�ʼ���ƣ���СΪ�ý�sh_size
			memcpy(symbol, (symshdr->sh_offset + mem), symshdr->sh_size);
			//��ȡ��ǰ�ڼ�.dynsym�ڵ����ݣ����������ű����ݣ������Ƶ�syms��
			if ((syms = (Elf32_Sym*)malloc(shdrp->sh_size)) == NULL) {
				printf("get_plt() malloc() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
				return MEM_ERR;
			}
			memcpy(syms, (shdrp->sh_offset + mem), shdrp->sh_size);
			
			//��λָ�룬��λ���ű��һ������
			symsp = syms;
			//������ű����ж��ٸ�
			sym_count = shdrp->sh_size / sizeof(Elf32_Sym);
			if ((link = (linking_info*)malloc(sizeof(linking_info) * sym_count)) == NULL) {
				printf("get_plt() malloc() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
				return MEM_ERR;
			}
			link[0].count = sym_count;
			
			for (int j = 0; j < sym_count; j++, symsp++) {
				//��ÿ����������ָ��Ƶ�link.name�У�������Դ�ڷ��ű�ʹ�õ�ǰ�����st_name����
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
			//��Ϊ�õ���size��������Ҫһ��һ�����������һ��һ����ִ����
			for (int j = 0; j < shdr->sh_size; j += sizeof(Elf32_Rel), rel++) {
				//��ѭ�������ض�λ�����б��
				for (int k = 0; k < sym_count; k++) {
					//��ѭ����Ϊ���ҵ���link[].index�͵�ǰ��ѭ���Ľ��ܶ�������˵�������ƫ�Ƶ���Ϣ�ǶԵġ�
					if (ELF32_R_SYM(rel->r_info) == link[k].index) {
						link[k].r_offset = rel->r_offset;
						link[k].r_info = rel->r_info;
						link[k].r_type = ELF32_R_TYPE(rel->r_info);
						//ԭ��û�����break
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

int add_symbol(char* name, Elf32_Addr vaddr, Elf32_Sym* sym, Elf32_mem_t* target) {
	int fd, st_index, sym_size = sizeof(Elf32_Sym);;
	Elf32_Off sym_offset;
	uint32_t st_offset, st_start;
	int s_len = strlen(name) + 1;
	name[strlen(name)] = 0;
	
	//.shstrtab�����ļ��е�ƫ��
	char* target_stbl = &target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];

	if ((fd = open(TEMP_FILE, O_CREAT | O_WRONLY | O_TRUNC, target->mode)) == -1) {
		printf("add_symbol() open() error\n");
		return OPFILE_ERR;
	}

	//�������ű�
	sym->st_value = vaddr;
	for (int i = 0; i < target->ehdr->e_shnum; i++) {
		if (target->shdr[i].sh_type == SHT_SYMTAB) {
			//�ҵ�.symtab�ڣ�������ElfN_Sym�ķ�����Ϣ��
			//ʹ��sym_offset��¼ֻ�ýڵ�ƫ��
			sym_offset = target->shdr[i].sh_offset + target->shdr[i].sh_size;
			target->shdr[i].sh_size += sym_size;
			//�Ӹýڿ�ʼ�������ÿһ���ڶ�Ҫ����ƶ�sym_size����С��
			while (i++ < target->ehdr->e_shnum) {
				target->shdr[i].sh_offset += sym_size;
			}
			//ԭ��û��break���Ҽ���һ�������ܻ�������ı��ֻҪһ��SHT_SYMTAB��
			break;
		}
	}

	for (int i = 0; i < target->ehdr->e_shnum; i++) {
		//��һ�׵���˼��֮���Ǳ���Ҫ.shstrtab�ڣ�Ҳ��Ҫ.strtab�ڣ�ֻҪ.dynstr��
		if (target->shdr[i].sh_type == SHT_STRTAB && i != target->ehdr->e_shstrndx &&
			strcmp(&target_stbl[target->shdr[i].sh_name], ".dynstr")) {
			//���ƫ�Ʋ��Ǻܶ�
			st_offset = target->shdr[i].sh_offset + target->shdr[i].sh_size - sym_size;
			st_index = i;
			//??Ϊʲô�ڳ��Ȼ��st_start?
			st_start = target->shdr[i].sh_size;
			target->shdr[i].sh_size += s_len;
			break;
		}
	}

	for (int i = 0; i < target->ehdr->e_shnum; i++) {
		//��st_index��һ���ڿ�ʼ,�޸���ʼ��ַ��ƫ�Ƶ�ַ
		if (i > st_index) {
			target->shdr[i].sh_offset += s_len;
			target->shdr[i].sh_addr += s_len;
		}
	}
	//�޸ķ�����Ϊ�µķ�����,�������������......
	sym->st_name = st_start;

	//д��ÿһ���飺
	if (write(fd, target->mem, sym_offset) != sym_offset) {
		printf("add_symbol() write() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
		return WTFILE_ERR;
	}
	if (write(fd, sym, sym_size) != sym_size) {
		printf("add_symbol() write() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
		return WTFILE_ERR;
	}
	if (write(fd, (target->mem + sym_offset), st_offset - sym_offset) != st_offset - sym_offset) {
		printf("add_symbol() write() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
		return WTFILE_ERR;
	}

	if (write(fd, name, s_len) != s_len) {
		printf("add_symbol() write() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
		return WTFILE_ERR;
	}

	if (write(fd, (target->mem + st_offset), target->size - st_offset) != target->size - st_offset) {
		printf("add_symbol() write() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
		return WTFILE_ERR;
	}
	char* tmp_name = "/home/orz/CLionProjects/xxxx/helloo";
	if (rename(TEMP_FILE, target->name) < 0) {
	//if(rename(TEMP_FILE, tmp_name) < 0){
		printf("add_symbol() rename() error, file:%s, line:%d\n", __FILE__, __LINE__ - 1);
		return CALL_ERR;
	}
	close(fd);

	target->size += sym_size;
	target->size += s_len;

	return SUCCESS;
}

Elf32_Addr get_base(Elf32_mem_t* target, int which)
{
	int i;

	for (i = 0; i < target->ehdr->e_phnum; i++)
		if ((target->phdr[i].p_offset == 0 || target->phdr[i].p_offset == 0x1000) && target->phdr[i].p_type == PT_LOAD)
		{
			if (which == TEXT)
				return target->phdr[i].p_vaddr;
			else
				if (which == DATA)
					return target->phdr[i + 1].p_vaddr;
				else
					return 0;
		}
	return 0;
}


Elf32_Sym* get_sym_by_name(char* name, Elf32_Shdr* shdr, int c, uint8_t* objmem)
{
	Elf32_Sym* symtab;
	Elf32_Shdr* shdrp;
	char* SymStrTable;
	int i, j, symcount;

	for (shdrp = shdr, i = 0; i < c; i++, shdrp++) {
		if (shdrp->sh_type == SHT_SYMTAB) {
			SymStrTable = &objmem[shdr[shdrp->sh_link].sh_offset];
			symtab = (Elf32_Sym*)&objmem[shdrp->sh_offset];

			for (j = 0; j < shdrp->sh_size / sizeof(Elf32_Sym); j++, symtab++) {
				if (strcmp(&SymStrTable[symtab->st_name], name) == 0)
					return symtab;
			}
		}
	}
	return NULL;
}

Elf32_Addr get_reloc_sym_addr(char* name, Elf32_Shdr* shdr, int c, uint8_t* objmem)
{
	Elf32_Sym* symtab;
	Elf32_Shdr* shdrp;
	char* SymStrTable;
	int i, j, symcount;

	for (shdrp = shdr, i = 0; i < c; i++, shdrp++) {
		if (shdrp->sh_type == SHT_SYMTAB) {
			SymStrTable = &objmem[shdr[shdrp->sh_link].sh_offset];
			symtab = (Elf32_Sym*)&objmem[shdrp->sh_offset];

			for (j = 0; j < shdrp->sh_size / sizeof(Elf32_Sym); j++, symtab++) {
				if (strcmp(&SymStrTable[symtab->st_name], name) == 0)
					return ((Elf32_Addr)shdr[symtab->st_shndx].sh_addr + symtab->st_value);
			}
		}
	}
	return 0;
}

Elf32_Addr get_sym_addr(char* name, Elf32_mem_t* target) {
	Elf32_Sym* symtab;
	char* sym_str_table;
	int sym_count;
	printf("name:%s\n", name);
	for (int i = 0; i < target->ehdr->e_phnum; i++) {
		if (target->shdr[i].sh_type == SHT_SYMTAB || target->shdr[i].sh_type == SHT_DYNSYM) {
			sym_str_table = (char*)target->section[target->shdr[i].sh_link];
			symtab = (Elf32_Sym*)target->section[i];

			for (int j = 0; j < target->shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++) {
				if (strcmp(&sym_str_table[symtab->st_name], name) == 0)
					return symtab->st_value;
				/*if (strcmp(&sym_str_table[symtab->st_name], "puts") == 0)
					return symtab->st_value;*/
			}
		}
	}
	return NULL;
}