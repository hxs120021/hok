#include "cmd.h"


int extract_args(char*** argvp, char* delim, char* s) {
    int tokens;
    char* t, * snew;
    //strspn���ز����Ҳ����ڶ����ַ������±�,snewָ���λ��
    snew = s + strspn(s, delim);
    //����arg1������΢arg2�Ŀռ䣬�����������ݶ����������ݣ�malloc���ʼ��Ϊ0
    if ((t = calloc(strlen(snew) + 1, sizeof(char))) == NULL)
    {
        *argvp = NULL;
        tokens = -1;
    }
    else
        strcpy(t, snew);

    //strtok����������η��أ�����ֻ��Ҫ�ڵ�һ��ָ��Ŀ��Ϳ����ˣ�����NULL�ͱ�ʾû��
    //��¼����������
    if (strtok(t, delim) == NULL)
        tokens = 0;
    else
        for (tokens = 1; strtok(NULL, delim) != NULL; tokens++);

    if ((*argvp = calloc(tokens + 1, sizeof(char*))) == NULL)
        tokens = -1;
    else if (tokens > 0)
    {
        //��ǰ�����ַ�Ϊ0
        bzero(t, strlen(snew));
        strcpy(t, snew);
        //��ÿһ�������Ž�ȥ
        **argvp = strtok(t, delim);
        int i;
        for (i = 1; i < tokens + 1; i++)
            *((*argvp) + i) = strtok(NULL, delim);
    }
    else
        **argvp = NULL;
    return tokens;
}

void main_loop() {
    elf_list* current, ** list_head = NULL;
    for (; ; ) {
        current = list_head;
        shell_do(&current, &list_head);
    }
}

int shell_do(elf_list** current, elf_list*** list_head) {
    char cmd[MAXSTR] = { 0 };
    char** args;
    int args_len;
    printf("orz@hok2: $ ");
    memset(cmd, 0, sizeof(cmd));
    fgets(cmd, sizeof(cmd) - 1, stdin);
    if (cmd[0] == '\n' || cmd[0] == '\r' || strlen(cmd) == 0)
        return CMD_ERR;

    if ((args_len = extract_args(&args, " ", cmd)) <= 1) {
        printf("need more arg\n");
        return ARGS_ERR;
    }
    if (strncasecmp(cmd, RELOCATE, strlen(RELOCATE)) == 0) {
        if (args_len < 3) {
            return ARGS_ERR;
        }

        return reloc(args, args_len, current, list_head);
    }
    return 1;
}

