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
    //目标中注入对象代码的地址
    obj_vaddr = target->phdr[TEXT].p_vaddr + target->phdr[TEXT].p_memsz;
    //调整节地址
    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        if (obj.shdr[i].sh_type == SHT_PROGBITS) {
            //在obj中重新构造TEXT段中每一个节的地址，是从obj_vaddr这个地方开始，依次往后放
            obj.shdr[i].sh_addr = obj_vaddr + sec_len;
            sec_len += obj.shdr[i].sh_size;
        }
        //找到.strtab节记录索引，不包括.shstrtab节，因为e_shstrndx就是节标题字符表，不要这个索引。
        if (obj.shdr[i].sh_type == SHT_STRTAB && i != obj.ehdr->e_shstrndx) {
            //符号字符串表索引 .strtab节索引
            sym_strndx = i;
        }
    }
    //根据索引找到.strtab节，符号字符串表内容。
    sym_string_table = obj.section[sym_strndx];
    //在目标进行重定位
    //在全部节中查找SHT_RELA/SHT_REL节
    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        switch (obj.shdr[i].sh_type)
        {
        case SHT_REL:
            //当前节在文件中的偏移，很神奇，这个偏移指向了一个偏移表项？？
            rel = (Elf32_Rel*)(obj.mem + obj.shdr[i].sh_offset);
            for (int j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Rel); j++, rel++) {
                //根据当前节的连接索引找到符号表
                symtab = (Elf32_Sym*)obj.section[obj.shdr[i].sh_link];
                //使用符号在符号表中的索引，找到符号表项
                symbol = &symtab[ELF32_R_SYM(rel->r_info)];
                //要修改的节
                target_section = &obj.shdr[obj.shdr[i].sh_info];
                target_index = obj.shdr[i].sh_info;
                //目标地址
                target_addr = target_section->sh_addr + rel->r_offset;
                //指向重新等位的目标
                reloc_ptr = (Elf32_Addr*)(obj.section[target_index] + rel->r_offset);
                //重新定位值
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
            //ElfN_Rel和ElfN_Rela区别只有a多了一个intN_t r_addend成员，用于重定位计算
            for (int j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Rela); j++, rela++) {
                //当前节在文件中的偏移,只一个重定位表
                rela = (Elf32_Rela*)(obj.shdr[i].sh_offset + obj.mem);
                //符号表，
                symtab = (Elf32_Sym*)obj.section[obj.shdr[i].sh_link];
                //符号表项，
                symbol = &symtab[ELF32_R_SYM(rela->r_info)];
                //要修改的节
                target_section = &obj.shdr[obj.shdr[i].sh_info];
                target_index = obj.shdr[i].sh_info;
                //目标地址
                target_addr = target_section->sh_addr + rela->r_offset;
                //重定位值
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
    //看上去像是复制TEXT段，把新生成的TEXT段复制到可执行文件中
    sec_len = 0;
    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        if (obj.shdr[i].sh_type == SHT_PROGBITS) {
            memcpy(&obj_code[sec_len], obj.section[i], obj.shdr[i].sh_size);
            sec_len += obj.shdr[i].sh_size;
        }
    }
    //注入重新定位的对象
    if ((obj_vaddr = inject_elf_binary(target, obj_code, tot_len, NO_JMP_CODE, type)) < 0) {
        printf("elf_relocate() inject_elf_binary() error\n");
        return CALL_ERR;
    }
    target_name = strdup(target->name);
    //卸载ELF，方便重定位有对象代码的版本
    if ((_err = load_elf(target_name, MAP_PRIVATE, PROT_READ | PROT_WRITE, 0, 0, &dst)) < 0) {
        printf("elr_relocate() load_elf() error\n");
        return _err;
    }

    for (int i = 0; i < obj.ehdr->e_shnum; i++) {
        if (obj.shdr[i].sh_type == SHT_SYMTAB) {
            //.strtab节和.shstrtab节
            //该节对应的符号名？
            sym_string_table = (char*)obj.section[obj.shdr[i].sh_link];
            //该节的符号项
            symtab = (Elf32_Sym*)obj.section[i];
            int st_type = ELF32_ST_TYPE(symtab->st_info);
            for (int j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++) {
                if (st_type == STT_FUNC || st_type == STT_OBJECT) {
                    //这个函数超级复杂。。。
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
                //分配调用适当的偏移量，公式：offset = address - callsite - 4
                long vaddr = *(long*)&dst.mem[dst.data_offset + lp[j].r_offset - dst.data_vaddr];
                long call_offset = lp[j].r_offset - function_call[i].vaddr - 4;
                
                //这一坨操作不是很懂。。。尤其是这三个数字是什么意思？
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