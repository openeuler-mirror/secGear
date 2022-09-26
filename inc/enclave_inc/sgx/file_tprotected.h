/* sgx_tprotected_fs.h */


#ifndef __SGX_TPROTECTED_H_
#define __SGX_TPROTECTED_H_

#include <stdint.h>
#include "string.h"
#include "sgx_tprotected_fs.h"


#define SGX_FILE void


SGX_FILE* get_fopen_ex(const char* filename, const char* mode);

size_t internel_fwrite_data(const void* ptr, size_t size, size_t count, SGX_FILE* stream);
size_t internel_fread_data(void* ptr, size_t size, size_t count, SGX_FILE* stream);

int32_t get_fclose_ex(SGX_FILE* stream);
int32_t get_remove_ex(const char* filename);

SGX_FILE* get_fopen_auto_key_ex(const char* filename, const char* mode);
int32_t get_fexport_auto_key_ex(const char* filename, void *key);
int32_t get_fimport_auto_key_ex(const char* filename, void *key);


#endif //__SGX_TPROTECTED_H_