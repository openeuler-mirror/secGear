/* sgx_tprotected_fs.h */


#ifndef SGX_TPROTECTED_H
#define SGX_TPROTECTED_H

#include <stdint.h>
#include "string.h"
#include "sgx_tprotected_fs.h"


#define SGX_FILE void


SGX_FILE* internel_fopen(const char* filename, const char* mode, void *key);

size_t internel_fwrite(const void* ptr, size_t size, size_t count, SGX_FILE* stream);
size_t internel_fread(void* ptr, size_t size, size_t count, SGX_FILE* stream);

int32_t internel_fclose(SGX_FILE* stream);
int32_t internel_remove(const char* filename);

SGX_FILE* internel_fopen_auto_key(const char* filename, const char* mode);
int32_t internel_fexport_auto_key(const char* filename, void *key);
int32_t internel_fimport_auto_key(const char* filename, void *key);


#endif //SGX_TPROTECTED_H