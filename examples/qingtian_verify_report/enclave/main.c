#include <stdio.h>
#include <unistd.h>

int main(void)
{
    while (1) {
        sleep(3);
        printf(".");
    }

    return 0;
}
