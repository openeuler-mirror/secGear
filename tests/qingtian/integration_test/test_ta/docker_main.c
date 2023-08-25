#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "secgear_log.h"

int main(void)
{
    PrintInfo(PRINT_DEBUG, "enclave start\n");
    while (1) {
        sleep(3);
        PrintInfo(PRINT_DEBUG, ".");
    }
    return 0;
}