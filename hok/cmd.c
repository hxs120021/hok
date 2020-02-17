#include "cmd.h"


int extract_args(char*** argvp, char* delim, char* s) {
    int tokens;
    char* t, * snew;
    //strspn返回不再找不到第二个字符串的下标,snew指向该位置
    snew = s + strspn(s, delim);
    //申请arg1个长度微arg2的空间，并且其中内容都是垃圾数据，malloc会初始化为0
    if ((t = calloc(strlen(snew) + 1, sizeof(char))) == NULL)
    {
        *argvp = NULL;
        tokens = -1;
    }
    else
        strcpy(t, snew);

    //strtok这个函数会多次返回，但是只需要在第一次指定目标就可以了，返回NULL就表示没了
    //记录参数个数。
    if (strtok(t, delim) == NULL)
        tokens = 0;
    else
        for (tokens = 1; strtok(NULL, delim) != NULL; tokens++);

    if ((*argvp = calloc(tokens + 1, sizeof(char*))) == NULL)
        tokens = -1;
    else if (tokens > 0)
    {
        //置前几个字符为0
        bzero(t, strlen(snew));
        strcpy(t, snew);
        //把每一个参数放进去
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

