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
	for (int i = 1; i < ehdr->e_shnum; shdrp++) {
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