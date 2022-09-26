#ifndef __ITRUSTEE_TPROTECTED_H_
#define __ITRUSTEE_TPROTECTED_H_

#include <stdint.h>
#include "string.h"

#include "tee_mem_mgmt_api.h"
#include "tee_trusted_storage_api.h"
#include "tee_defines.h"

//uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
//uint32_t r_flags = TEE_DATA_FLAG_ACCESS_READ;
//uint32_t w_flags = TEE_DATA_FLAG_ACCESS_WRITE;
//void *create_objectID = "store_data_sample.txt";
//TEE_ObjectHandle persistent_data = NULL;
//TEE_Result ret;

//uint32_t pos = 0;
//uint32_t len = 0;
//char *read_buffer = NULL;
//uint32_t count = 0;
#define ITRUSTEE_FILE void

ITRUSTEE_FILE* get_fopen_ex(const char* filename, const char* mode);

size_t internel_fwrite_data(const void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream);
size_t internel_fread_data(void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream);

int32_t get_fclose_ex(ITRUSTEE_FILE* stream);
ITRUSTEE_FILE* get_fopen_auto_key_ex(const char* filename, const char* mode);

int32_t get_remove_ex(const char* filename);
int32_t get_fexport_auto_key_ex(const char* filename, void *key);
int32_t get_fimport_auto_key_ex(const char* filename, void *key);


#endif //__ITRUSTEE_TPROTECTED_H_