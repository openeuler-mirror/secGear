#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    printf("enclave start\n");
    while (1) {
        sleep(3);
        printf(".");
    }
    return 0;
}