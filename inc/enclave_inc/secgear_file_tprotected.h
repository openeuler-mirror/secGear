#ifndef __SECGEAR_FILE_TPROTECTED_API_H
#define __SECGEAR_FILE_TPROTECTED_API_H

#include <stdio.h>
#include <stdint.h>
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILE_PTR void

FILE_PTR* cc_enclave_get_fopen(const char* filename, const char* mode);
cc_enclave_result_t cc_enclave_fwrite_data(const void* ptr, size_t size, size_t count, FILE_PTR* stream);
cc_enclave_result_t cc_enclave_fread_data(void* ptr, size_t size, size_t count, FILE_PTR* stream);

cc_enclave_result_t cc_enclave_get_fclose(FILE_PTR* stream);
cc_enclave_result_t cc_enclave_get_remove(const char* filename);

FILE_PTR* cc_enclave_get_fopen_auto_key(const char* filename, const char* mode);
cc_enclave_result_t cc_enclave_get_fexport_auto_key(const char* filename, void *key);
cc_enclave_result_t cc_enclave_get_fimport_auto_key(const char* filename, void *key);


#ifdef __cplusplus
}
#endif
#endif
