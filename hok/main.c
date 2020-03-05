#include "cmd.h"

int main() {
    printf("file:%s, line:%d\n", __FILE__, __LINE__);
    main_loop();
    return 0;
}
