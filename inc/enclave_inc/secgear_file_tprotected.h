#ifndef SECGEAR_FILE_TPROTECTED_API_H
#define SECGEAR_FILE_TPROTECTED_API_H

#include <stdio.h>
#include <stdint.h>
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILE_PTR void

FILE_PTR* cc_enclave_fopen(const char* filename, const char* mode, void *key);

/*
 * cc_enclave_fwrite used to write the string
 *
 * param ptr        [IN] the string data
 * param size       [IN] the type size
 * param count      [IN] the number of types
 *
 * retval CC_ERROR_GENERIC    means function fails
 * retvel CC_SUCCESS          means function success
 */
cc_enclave_result_t cc_enclave_fwrite(const void* ptr, size_t size, size_t count, FILE_PTR* stream);

/*
 * cc_enclave_fread used to write the string
 *
 * param ptr        [IN] the string data
 * param size       [IN] the type size
 * param count      [IN] the number of types
 *
 * retval CC_ERROR_GENERIC    means function fails
 * retvel CC_SUCCESS          means function success
 */
cc_enclave_result_t cc_enclave_fread(void* ptr, size_t size, size_t count, FILE_PTR* stream);

cc_enclave_result_t cc_enclave_fclose(FILE_PTR* stream);
cc_enclave_result_t cc_enclave_remove(const char* filename);

FILE_PTR* cc_enclave_fopen_auto_key(const char* filename, const char* mode);
cc_enclave_result_t cc_enclave_fexport_auto_key(const char* filename, void *key);
cc_enclave_result_t cc_enclave_fimport_auto_key(const char* filename, void *key);


#ifdef __cplusplus
}
#endif
#endif
