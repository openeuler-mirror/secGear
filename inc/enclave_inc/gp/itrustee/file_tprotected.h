#ifndef ITRUSTEE_TPROTECTED_H
#define ITRUSTEE_TPROTECTED_H

#include <stdint.h>
#include "string.h"


#define ITRUSTEE_FILE void

ITRUSTEE_FILE* internel_fopen(const char* filename, const char* mode, void *key);

size_t internel_fwrite(const void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream);
size_t internel_fread(void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream);

int32_t internel_fclose(ITRUSTEE_FILE* stream);
int32_t internel_remove(const char* filename);

ITRUSTEE_FILE* internel_fopen_auto_key(const char* filename, const char* mode);

int32_t internel_fexport_auto_key(const char* filename, void *key);
int32_t internel_fimport_auto_key(const char* filename, void *key);


#endif //ITRUSTEE_TPROTECTED_H