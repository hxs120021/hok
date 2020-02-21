
#ifndef _CMD_H_
#define _CMD_H_

#include "hok.h"
#include "reloc.h"
#include "hijack.h"

#define RELOCATE	"reloc"
#define HIJACK		"hijack"
#define INJECT		"inject"

#define BINARY_MODE		"binary"
#define PROCESS_MODE	"process"


//分解参数，返回参数个数，对s使用delim分割符，最终分割的存放在argvp中
int extract_args(char*** argvp, char* delim, char* s);

//形成一个类似命令行的可以交互的接口
void main_loop();

//单次交互内容
int shell_do(elf_list** current, elf_list*** list_head);

int is_int(char* p);

#endif