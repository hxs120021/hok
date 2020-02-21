
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


//�ֽ���������ز�����������sʹ��delim�ָ�������շָ�Ĵ����argvp��
int extract_args(char*** argvp, char* delim, char* s);

//�γ�һ�����������еĿ��Խ����Ľӿ�
void main_loop();

//���ν�������
int shell_do(elf_list** current, elf_list*** list_head);

int is_int(char* p);

#endif