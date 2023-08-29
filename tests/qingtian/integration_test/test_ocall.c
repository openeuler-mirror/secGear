#include <stdio.h>
int increase_result(int who, int a)
{
    printf("[%d] set %d\n", who, a);
    return a;
}

void ocall_void_void(void)
{
    printf("ocall_void_void be called\n");
}