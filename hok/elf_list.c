#include "elf_list.h"



elf_list* add_elf(char* name, elf_list** root) {
	elf_list* tmp;

	if ((tmp = (elf_list*)malloc(sizeof(elf_list))) == NULL) {
		perror("add_elf() malloc\n");
		return MEM_ERR;
	}

	strncpy(tmp->name, name, sizeof(tmp->name));
	tmp->name[sizeof(tmp->name) - 1] = 0;

	if (load_elf(name, MAP_SHARED, PROT_READ | PROT_WRITE, 0, 0, &tmp->elf) < 0) {
		printf("add_elf() loadelf() error\n");
		return CALL_ERR;
	}

	tmp->next = *root;
	*root = tmp;
	return *root;
}

int remove_elf(elf_list** current) {
	elf_list* tmp;
	if (current != NULL) {
		unload_elf(&(*current)->elf);
		tmp = (*current)->next;
		free(*current);
		*current = tmp;
		return SUCCESS;
	}
	return MEM_ERR;
}

elf_list** search_by_name(char* name, struct elf_list** current) {
	while (*current != NULL) {
		if (strcmp((*current)->name, name) == 0) {
			return current;
		}
		current = &(*current)->next;
	}
	return NULL;
}