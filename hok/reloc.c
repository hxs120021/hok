#include"reloc.h"

int reloc(char** args, int args_len, elf_list** current, elf_list*** list_head) {
    char target_name[MAXSTR], source_name[MAXSTR];
    
    strncpy(source_name, args[1], MAXSTR);
    strncpy(target_name, args[2], MAXSTR);
    source_name[sizeof(source_name) - 1] = 0;
    target_name[sizeof(target_name) - 1] = 0;
    
    *current = (elf_list*)add_elf(target_name, *list_head);
    if (elf_relocate(&((*current)->elf), source_name, TEXT_PADDING_INFECTION) > 0) {
        printf("Injection / Relocation successs\n");
    }
    else {
        printf("Injection / Relocation failed\n");
        return CALL_ERR;
    }
    free(args);
    return SUCCESS;
}

int elf_relocate(Elf32_mem_t* target, char* name, int type) {
    Elf32_Sym* symtab, * symbol;
    Elf32_Shdr* target_section;
    Elf32_Addr target_addr, rel_val, * reloc_ptr;
    
    int target_index, fd, sym_strndx;
    char* sym_name, * target_name;
    STAT st;

    Elf32_Addr obj_vaddr;
    Elf32_mem_t dst;
    Elf32_Rel* rel;
    Elf32_Rela* rela;
    Elf32_Sym* sym;

    int fnc = 0;
    Elf32_mem_t obj;

    char* sym_string_table;
    uint32_t tot_len, sec_len = 0;
    uint8_t* obj_code;

    struct{
        char* function;
        unsigned long vaddr;
    } function_call[4096 * 2];
    int _err;
    if ((_err = load_elf(name, MAP_PRIVATE, PROT_READ | PROT_WRITE, 0, 0, &obj)) < 0) {
        printf("elf_relocate() load_elf() error\n");
        return _err;
    }

    for (int i = 0, tot_len = 0; i < obj.ehdr->e_shnum; i++) {
        if (obj.shdr[i].sh_type == SHT_PROGBITS) {
            tot_len += obj.shdr[i].sh_size;
        }
    }
    if ((obj_code = (uint8_t*)malloc(tot_len)) == NULL)
        return MEM_ERR;
    //Ŀ����ע��������ĵ�ַ
    obj_vaddr = target->phdr[TEXT].p_vaddr + target->phdr[TEXT].p_memsz;
    //�����ڵ�ַ
    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        if (obj.shdr[i].sh_type == SHT_PROGBITS) {
            //��obj�����¹���TEXT����ÿһ���ڵĵ�ַ���Ǵ�obj_vaddr����ط���ʼ�����������
            obj.shdr[i].sh_addr = obj_vaddr + sec_len;
            sec_len += obj.shdr[i].sh_size;
        }
        //�ҵ�.strtab�ڼ�¼������������.shstrtab�ڣ���Ϊe_shstrndx���ǽڱ����ַ�����Ҫ���������
        if (obj.shdr[i].sh_type == SHT_STRTAB && i != obj.ehdr->e_shstrndx) {
            //�����ַ��������� .strtab������
            sym_strndx = i;
        }
    }
    //���������ҵ�.strtab�ڣ������ַ��������ݡ�
    sym_string_table = obj.section[sym_strndx];
    //��Ŀ������ض�λ
    //��ȫ�����в���SHT_RELA/SHT_REL��
    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        switch (obj.shdr[i].sh_type)
        {
        case SHT_REL:
            //��ǰ�����ļ��е�ƫ�ƣ������棬���ƫ��ָ����һ��ƫ�Ʊ����
            rel = (Elf32_Rel*)(obj.mem + obj.shdr[i].sh_offset);
            for (int j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Rel); j++, rel++) {
                //���ݵ�ǰ�ڵ����������ҵ����ű�
                symtab = (Elf32_Sym*)obj.section[obj.shdr[i].sh_link];
                //ʹ�÷����ڷ��ű��е��������ҵ����ű���
                symbol = &symtab[ELF32_R_SYM(rel->r_info)];
                //Ҫ�޸ĵĽ�
                target_section = &obj.shdr[obj.shdr[i].sh_info];
                target_index = obj.shdr[i].sh_info;
                //Ŀ���ַ
                target_addr = target_section->sh_addr + rel->r_offset;
                //ָ�����µ�λ��Ŀ��
                reloc_ptr = (Elf32_Addr*)(obj.section[target_index] + rel->r_offset);
                //���¶�λֵ
                rel_val = symbol->st_value;
                rel_val += obj.shdr[symbol->st_shndx].sh_addr;
                printf("0x%08x %s addr: 0x%x\n", rel_val, &sym_string_table[symbol->st_name], target_addr);
                //gotta complete hueristics here
                if (rel_val == 0) {
                    function_call[fnc].function = strdup(&sym_string_table[symbol->st_name]);
                    function_call[fnc].vaddr = target_addr;
                    printf("function : %s\n", function_call[fnc].function);
                    fnc++;
                }
                switch (ELF32_R_TYPE(rel->r_info)) {
                case R_386_PC32:
                    *reloc_ptr += rel_val;
                    *reloc_ptr -= target_addr;
                    break;
                case R_386_32:
                    *reloc_ptr += rel_val;
                    break;
                }
            }
            break;
        case SHT_RELA:
            //ElfN_Rel��ElfN_Rela����ֻ��a����һ��intN_t r_addend��Ա�������ض�λ����
            for (int j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Rela); j++, rela++) {
                //��ǰ�����ļ��е�ƫ��,ֻһ���ض�λ��
                rela = (Elf32_Rela*)(obj.shdr[i].sh_offset + obj.mem);
                //���ű�
                symtab = (Elf32_Sym*)obj.section[obj.shdr[i].sh_link];
                //���ű��
                symbol = &symtab[ELF32_R_SYM(rela->r_info)];
                //Ҫ�޸ĵĽ�
                target_section = &obj.shdr[obj.shdr[i].sh_info];
                target_index = obj.shdr[i].sh_info;
                //Ŀ���ַ
                target_addr = target_section->sh_addr + rela->r_offset;
                //�ض�λֵ
                rel_val = symbol->st_value;
                rel_val += obj.shdr[symbol->st_shndx].sh_addr;

                switch (ELF32_R_TYPE(rela->r_info)) {
                case R_386_PC32:
                    *reloc_ptr += rel_val;
                    *reloc_ptr += rela->r_addend;
                    *reloc_ptr -= target_addr;
                    break;
                case R_386_32:
                    *reloc_ptr += rel_val;
                    *reloc_ptr += rela->r_addend;
                    break;
                }
            }
            break;
        }
    }
    //����ȥ���Ǹ���TEXT�Σ��������ɵ�TEXT�θ��Ƶ���ִ���ļ���
    sec_len = 0;
    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        if (obj.shdr[i].sh_type == SHT_PROGBITS) {
            memcpy(&obj_code[sec_len], obj.section[i], obj.shdr[i].sh_size);
            sec_len += obj.shdr[i].sh_size;
        }
    }
    //ע�����¶�λ�Ķ���
    if ((obj_vaddr = inject_elf_binary(target, obj_code, tot_len, NO_JMP_CODE, type)) < 0) {
        printf("elf_relocate() inject_elf_binary() error\n");
        return CALL_ERR;
    }
    target_name = strdup(target->name);
    //ж��ELF�������ض�λ�ж������İ汾
    if ((_err = load_elf(target_name, MAP_PRIVATE, PROT_READ | PROT_WRITE, 0, 0, &dst)) < 0) {
        printf("elr_relocate() load_elf() error\n");
        return _err;
    }

    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        if (obj.shdr[i].sh_type == SHT_SYMTAB) {
            //.strtab�ں�.shstrtab��
            //�ýڶ�Ӧ�ķ�������
            sym_string_table = (char*)obj.section[obj.shdr[i].sh_link];
            //�ýڵķ�����
            symtab = (Elf32_Sym*)obj.section[i];
            int st_type = ELF32_ST_TYPE(symtab->st_info);
            for (int j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++) {
                if (st_type == STT_FUNC || st_type == STT_OBJECT) {
                    //��������������ӡ�����
                    add_symbol(&sym_string_table[symtab->st_name],
                        get_reloc_sym_addr(&sym_string_table[symtab->st_name], obj.shdr, obj.ehdr->e_shnum, obj.mem),
                        get_sym_by_name(&sym_string_table[symtab->st_name], obj.shdr, obj.ehdr->e_shnum, obj.mem),
                        &dst);
                    if ((_err = reload_elf(&dst)) < 0) {
                        printf("elf_relocate() reload_elf() error\n");
                        return _err;
                    }
                }
            }
        }
    }
    unload_elf(&obj);

    linking_info* lp;
    int c;
    for (int i = 0; i < fnc; i++) {
        if ((lp = (linking_info*)get_plt(dst.mem)) == NULL) {
            printf("elf_relocate() get_plt() error\nunable to get GOT/PLT info\n");
            return INFO_ERR;
        }
        for (int j = 0; j < lp[0].count; j++) {
            if (strcmp(lp[j].name, function_call[i].function) == 0) {
                //��������ʵ���ƫ��������ʽ��offset = address - callsite - 4
                long vaddr = *(long*)&dst.mem[dst.data_offset + lp[j].r_offset - dst.data_vaddr];
                long call_offset = lp[j].r_offset - function_call[i].vaddr - 4;
                
                //��һ��������Ǻܶ�������������������������ʲô��˼��
                *(uint8_t*)&dst.mem[(function_call[i].vaddr - get_base(&dst, TEXT)) - 1] = 0xff;
                *(uint8_t*)&dst.mem[function_call[i].vaddr - get_base(&dst, TEXT)] = 0x15;  // = call_offset;
                *(unsigned long*)&dst.mem[function_call[i].vaddr - get_base(&dst, TEXT) + 1] = lp[j].r_offset;
                
                reload_elf(&dst);
            }
        }
    }

    unload_elf(&dst);
    free(target);
    return SUCCESS;
}