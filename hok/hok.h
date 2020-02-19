#ifndef _HOK_H_
#define _HOK_H_

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <pthread.h>

#define SUCCESS 1
#define FAILURE 0
#define WHITE "\033[0;37m"
#define RED   "\033[0;31m"
#define GREEN "\033[0;32m"
#define BLUE  "\033[0;34m"
#define END   "\033[0m"

#define TEMP_FILE	"temp_bin"
#define MAXSTR		255

#define NO_JMP_CODE ~0L

#define TEXT_PADDING_INFECTION  1
#define DATA_INFECTION          2
#define DATA    1
#define TEXT    2

#define SUCCESS		1

#define CMD_ERR		-1
#define ARGS_ERR	-2
#define SYS_ERR     -3
#define MEM_ERR     -4
#define NULL_ERR    -5
#define CALL_ERR    -6
#define INFO_ERR    -7
#define FILE_ERR	-128
#define OPFILE_ERR	-129
#define CLOFIL_ERR  -130
#define WTFILE_ERR  -131
#define RDFILE_REE  -132


typedef struct stat STAT;

typedef struct linking_info {
    char name[256];
    int index;
    int count;
    uint32_t r_offset;
    uint32_t r_info;
    uint32_t s_value;
    int r_type;
}linking_info;

typedef struct Elf32_mem_t {
    //elf raw memory
    uint8_t* mem;
    //elf headers
    Elf32_Shdr* shdr;
    Elf32_Phdr* phdr;
    Elf32_Ehdr* ehdr;
    //sections
    uint8_t** section;
    //file size
    uint32_t size;
    //file mode
    int mode;
    //ET_DNY | ET_REL | ET_EXEC
    int elf_type;
    //file name
    char name[MAXSTR];
    //代码段和数据段的虚拟地址
    Elf32_Addr text_vaddr;
    Elf32_Addr data_vaddr;
    Elf32_Off text_offset;
    Elf32_Off data_offset;

    unsigned long text_filesz;
    unsigned long text_memsz;
    unsigned long data_filesz;
    unsigned long data_memsz;

    char* typestr[7];
}Elf32_mem_t;

typedef struct elf_list {
    Elf32_mem_t elf;
    char name[MAXSTR];
    struct elf_list* next;
}elf_list;

#endif