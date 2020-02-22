#include "hijack.h"
//hijack <mode:binary/process> <target:binary file/pid> <parasite function> <target function>
//args[0]	args[1]				args[2]					args[3]				args[4]
int hijack(char** args, int args_len, elf_list** current, elf_list*** list_head) {
	int hijack_mode, ret;

	if (strcasecmp(args[1], "binary") == 0) {
		*current = (elf_list*)add_elf(args[2], *list_head);
		if (!current) {
			printf("hijack() add_elf() error\n");
			return CALL_ERR;
		}
		hijack_mode = BINARY_MODE_HIJACK;
	}
	else if (strcasecmp(args[1], "process") == 0) {
		if (!is_int(args[2])) {
			printf("get a number for pid\n");
			return ARGS_ERR;
		}
		hijack_mode = PROCESS_MODE_HIJACK;
	}
	else {
		printf("get a args elf/pid: binary/<int>\n");
		return ARGS_ERR;
	}

	unsigned long sym_vaddr = get_sym_addr(args[3], &((*current)->elf));
	if (sym_vaddr == 0) {
		printf("hijack() get_sym_addr() error\n");
		return CALL_ERR;
	}
	if (hijack_mode == BINARY_MODE_HIJACK) {
		//char *strchr(const char *str, int c) 第一次出现字符的位置
		*(char*)strchr(args[4], '\n') = '\0';
		ret = hijack_function(&((*current)->elf), hijack_mode, sym_vaddr, args[4]);
	}
	else {
		ret = hijack_function(NULL, hijack_mode, sym_vaddr, args[4]);
	}

	if (hijack_mode == BINARY_MODE_HIJACK && !ret) {
		printf("commiting changes into executable file\n");
		commit_changes(&((*current)->elf));
		remove_elf((elf_list**)search_by_name(args[2], *list_head));
	}

	return SUCCESS;
}

int hijack_function(Elf32_mem_t* target, int mode, unsigned long new_vaddr, char* function) {
	uint8_t* mem;
	Elf32_Dyn* dyn;
	linking_info* lp;
	unsigned long got_entry = 0;

	switch (mode) {
	case BINARY_MODE_HIJACK:
		printf("hijack to function : %s\n", function);
		for (int i = 0; i < target->ehdr->e_phnum; i++) {
			if (target->phdr->p_type == PT_DYNAMIC) {
				dyn = (Elf32_Dyn*)(target->phdr[i].p_offset + mem);
				break;
			}
		}

		if ((lp = (linking_info*)get_plt(target->mem)) == NULL) {
			printf("hijack_function() get_plt() error\n");
			return CALL_ERR;
		}

		for (int i = 0; i < lp[0].count; i++) {
			if (strcmp(lp[i].name, function) == 0) {
				got_entry = target->data_offset + lp[i].r_offset - target->data_vaddr;
				printf("GOT offset for %s : 0x%x\n", lp[i].name, got_entry);
				break;
			}
		}

		if (got_entry == 0) {
			printf("hijack_function() got_entry value error, file:%s, line:%d\n", __FILE__, __LINE__);
			return VALUE_ERR;
		}
		printf("modefying got entry for %s\n", function);
		*(unsigned long*)&target->mem[got_entry] = new_vaddr;
		break;
	case PROCESS_MODE_HIJACK:
		printf("not this mode\n");
		return CALL_ERR;
	}
	return SUCCESS;
}